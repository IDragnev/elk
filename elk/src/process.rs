use mmap::{
    MemoryMap,
    MapOption,
};
use multimap::MultiMap;
use custom_debug_derive::Debug as CustomDebug;
use std::{
    path::{
        PathBuf,
        Path,
    },
    fs,
    collections::{
        HashMap,
    },
    ops::Range,
    cmp::{
        min,
        max,
    },
    sync::Arc,
};
use enumflags2::BitFlags;
use crate::name::Name;

#[derive(CustomDebug)]
pub struct Segment {
    #[debug(skip)]
    pub map: Arc<MemoryMap>,
    pub vaddr_range: Range<delf::Addr>,
    pub padding: delf::Addr,
    pub flags: BitFlags<delf::SegmentFlag>,
}

#[derive(CustomDebug)]
pub struct Object {
    pub path: PathBuf,
    pub base: delf::Addr,
    pub mem_range: Range<delf::Addr>,
    pub loaded_segments: Vec<Segment>,
    #[debug(skip)]
    pub file: delf::File,
    #[debug(skip)]
    syms: Vec<NamedSym>,
    #[debug(skip)]
    sym_map: MultiMap<Name, NamedSym>,
    #[debug(skip)]
    pub relocations: Vec<delf::Rela>,
}

#[derive(thiserror::Error, Debug)]
pub enum LoadError {
    #[error("ELF object not found: {0}")]
    NotFound(String),
    #[error("And invalid or unsupported path was encountered")]
    InvalidPath(PathBuf),
    #[error("I/O error: {0} - {1}")]
    IO(PathBuf, std::io::Error),
    #[error("ELF object could not be parsed: {0}")]
    ParseError(PathBuf),
    #[error("ELF object has no load segments")]
    NoLoadSegments,
    #[error("ELF object could not be mapped in memory: {0}")]
    MapError(#[from] mmap::MapError),   
    #[error("Could not read symbols from ELF object: {0}")]
    ReadSymsError(#[from] delf::ReadSymsError),
    #[error("Could not read relocations from ELF object: {0}")]
    ReadRelaError(#[from] delf::ReadRelaError),
}

#[derive(thiserror::Error, Debug)]
pub enum RelocationError {
    #[error("{0:?}: unimplemented relocation: {1:?}")]
    UnimplementedRelocation(PathBuf, delf::RelType),
    #[error("Unknown symbol number: {0}")]
    UnknownSymbolNumber(u32),
    #[error("Undefined symbol: {0:?}")]
    UndefinedSymbol(NamedSym),
}

#[derive(Debug, Clone)]
pub struct NamedSym {
    sym: delf::Sym,
    name: Name,
}

#[derive(Debug, Clone)]
struct ObjectSym<'a> { 
    obj: &'a Object,
    sym: &'a NamedSym,
}

impl ObjectSym<'_> {
    fn value(&self) -> delf::Addr {
        self.obj.base + self.sym.sym.value
    }
}

#[derive(Debug, Clone)]
enum ResolvedSym<'a> {
    Defined(ObjectSym<'a>),
    Undefined,
}

impl ResolvedSym<'_> {
    fn value(&self) -> delf::Addr {
        match self {
            Self::Defined(sym) => sym.value(),
            Self::Undefined => delf::Addr(0x0),
        }
    }

    fn size(&self) -> usize {
        match self {
            Self::Defined(sym) => sym.sym.sym.size as usize,
            Self::Undefined => 0,
        }
    }
}

#[derive(Debug)]
struct ObjectRel<'a> {
    obj: &'a Object,
    rel: &'a delf::Rela,
}

impl ObjectRel<'_> {
    fn addr(&self) -> delf::Addr {
        self.obj.base + self.rel.offset
    }
}

#[derive(Debug)]
pub struct Loader {
    pub objects: Vec<Object>,
    pub objects_by_path: HashMap<PathBuf, usize>,
    pub search_path: Vec<PathBuf>,
}

pub trait ProcessState {
    fn loader(&self) -> &Loader;
}

pub struct Process<S: ProcessState> {
    pub state: S,
}

pub struct Loading {
    pub loader: Loader,
}

pub struct TLS {
    // offset to the left of tcb_addr for each loaded ELF object
    offsets: HashMap<delf::Addr, delf::Addr>,
    block: Vec<u8>,
    pub tcb_addr: delf::Addr,
}

pub struct TLSAllocated {
    pub loader: Loader,
    pub tls: TLS,
}

pub struct Relocated {
    loader: Loader,
    tls: TLS,
}

pub struct TLSInitialized {
    loader: Loader,
    tls: TLS,
}

pub struct Protected {
    pub loader: Loader,
    pub tls: TLS,
}

impl ProcessState for Loading {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

impl ProcessState for TLSAllocated {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

impl ProcessState for Relocated {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

impl ProcessState for TLSInitialized {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

impl ProcessState for Protected {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

pub enum GetResult {
    Cached(usize),
    Fresh(usize),
}

impl GetResult {
    fn fresh(self) -> Option<usize> {
        if let Self::Fresh(index) = self {
            Some(index)
        } else {
            None
        }
    }
}

impl Process<Loading> {
    pub fn new() -> Self {
        Self {
            state: Loading {
                loader: Loader {
                    objects: Vec::new(),
                    objects_by_path: HashMap::new(),
                    search_path: vec![
                        "/usr/lib".into(),
                        "/lib/x86_64-linux-gnu".into(), // WSL
                    ],
                },
            },
        }
    }

    pub fn load_object_and_dependencies<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<usize, LoadError> {
        let index = self.load_object(path)?;

        // load all dependencies using BFS
        let mut a = vec![index];
        while a.is_empty() == false {
            a = a
                .into_iter()
                .map(|index| &self.state.loader.objects[index].file)
                .flat_map(|file| file.dynamic_entry_strings(delf::DynamicTag::Needed))
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect::<Vec<_>>()
                .into_iter()
                .map(|dep| self.get_object(&dep))
                .collect::<Result<Vec<GetResult>, LoadError>>()?
                .into_iter()
                .filter_map(GetResult::fresh)
                .collect();
        }

        Ok(index)
    }

    pub fn load_object<P: AsRef<Path>>(&mut self, path: P) -> Result<usize, LoadError> {
        use std::io::Read;

        let path: PathBuf = path.as_ref()
                                .canonicalize()
                                .map_err(|e| LoadError::IO(path.as_ref().to_path_buf(), e))?;

        let mut fs_file = fs::File::open(&path).map_err(|e| LoadError::IO(path.clone(), e))?;
        let mut input = Vec::new();
        fs_file.read_to_end(&mut input).map_err(|e| LoadError::IO(path.clone(), e))?;

        println!("Loading {:?}", path);
        let file = delf::File::parse_or_print_error(&input[..])
            .ok_or_else(|| LoadError::ParseError(path.clone()))?;

        let origin = path.parent()
                         .ok_or_else(|| LoadError::InvalidPath(path.clone()))?
                         .to_str()
                         .ok_or_else(|| LoadError::InvalidPath(path.clone()))?;

        for rpath in file.dynamic_entry_strings(delf::DynamicTag::RunPath) {
            let rpath = String::from_utf8_lossy(rpath);
            let rpath = rpath.replace("$ORIGIN", &origin);
            println!("Found RPATH entry {:?}", rpath);

            self.state.loader.search_path.push(PathBuf::from(rpath));
        }

        let load_segments = || {
            file.program_headers
                .iter()
                .filter(|ph| ph.r#type == delf::SegmentType::Load)
        };

        let mem_range = load_segments()
                        .map(|ph| ph.mem_range())
                        .fold(None, |acc, mem_range| {
                            match acc {
                                None => Some(mem_range),
                                Some(acc) => Some(convex_hull(acc, mem_range)),
                            }
                        })
                        .ok_or_else(|| LoadError::NoLoadSegments)?;

        let mem_size: usize = (mem_range.end - mem_range.start).into();
        let mem_map = std::mem::ManuallyDrop::new(MemoryMap::new(
            mem_size,
             &[MapOption::MapReadable, MapOption::MapWritable],
        )?);
        let base = delf::Addr(mem_map.data() as _) - mem_range.start;

        let loaded_segments = load_segments()
            .filter(|ph| ph.memsz.0 > 0)
            .map(|ph| -> Result<_, LoadError> {
                use std::os::unix::io::AsRawFd;

                let vaddr = delf::Addr(ph.vaddr.0 & !0xFFF);
                let padding = ph.vaddr - vaddr;
                let offset = ph.offset - padding;
                let filesz = ph.filesz + padding;

                let map = MemoryMap::new(
                        filesz.into(),
                        &[
                            MapOption::MapReadable,
                            MapOption::MapWritable,
                            MapOption::MapExecutable,
                            MapOption::MapFd(fs_file.as_raw_fd()),
                            MapOption::MapOffset(offset.into()),
                            MapOption::MapAddr((base + vaddr).as_ptr()),
                        ],
                )?;

                // zero any additional bytes
                if ph.memsz > ph.filesz {
                    let mut zero_start = base + ph.mem_range().start + ph.filesz;
                    let zero_len = ph.memsz - ph.filesz;
                    unsafe {
                        for i in zero_start.as_mut_slice(zero_len.into()) {
                            *i = 0u8;
                        }
                    }
                }

                Ok(Segment {
                    map: Arc::new(map),
                    vaddr_range: vaddr..(ph.vaddr + ph.memsz),
                    padding,
                    flags: ph.flags,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let syms = file.read_dynsym_entries()?;
        let syms: Vec<_> = if syms.is_empty() {
            vec![]
        }
        else {
            let dynstr_addr = file.get_dynamic_entry(delf::DynamicTag::StrTab)
                                  .unwrap_or_else(|_| panic!("String table not found in {:?}", path));
            let dynstr_segment = loaded_segments
                .iter()
                .find(|seg| seg.vaddr_range.contains(&dynstr_addr))
                .unwrap_or_else(|| panic!("Segment not found for string table in {:#?}", path));

            syms.into_iter()
                .map(|sym| {
                    let name = Name::mapped(
                        &dynstr_segment.map,
                        (dynstr_addr + sym.name - dynstr_segment.vaddr_range.start).into(),
                    );
                    NamedSym { sym, name }
                })
                .collect()
        };

        let mut sym_map = MultiMap::new();
        for sym in &syms {
            sym_map.insert(sym.name.clone(), sym.clone());
        }

        let mut relocations = file.read_rela_entries()?; 
        relocations.extend(file.read_jmp_rel_entries()?);

        let obj = Object {
            path: path.clone(),
            base,
            loaded_segments,
            file,
            mem_range,
            syms,
            sym_map,
            relocations,
        };
        let index = self.state.loader.objects.len();
        self.state.loader.objects.push(obj);
        self.state.loader.objects_by_path.insert(path, index);

        Ok(index)
    }

    pub fn get_object(&mut self, name: &str) -> Result<GetResult, LoadError> {
        let path = self.object_path(name)?;
        self.state
            .loader
            .objects_by_path
            .get(&path)
            .map(|&index| Ok(GetResult::Cached(index)))
            .unwrap_or_else(|| self.load_object(path).map(GetResult::Fresh))
    }

    pub fn object_path(&self, name: &str) -> Result<PathBuf, LoadError> {
        self.state
            .loader
            .search_path
            .iter()
            .filter_map(|prefix| prefix.join(name).canonicalize().ok())
            .find(|path| path.exists())
            .ok_or_else(|| LoadError::NotFound(name.into()))
    }

    pub fn allocate_tls(mut self) -> Process<TLSAllocated> {
        let mut offsets = HashMap::new();
        // total space needed for all thread-local variables of all ELF objects
        let mut storage_space = 0;

        for obj in &mut self.state.loader.objects {
            let needed_space = obj
                .file
                .segment_of_type(delf::SegmentType::TLS)
                .map(|ph| ph.memsz.0)
                .unwrap_or_default() as u64;

            if needed_space > 0 {
                // backwards offset (to the start address for this ELF)
                // going left from tcb_addr
                let offset = delf::Addr(storage_space + needed_space);
                offsets.insert(obj.base, offset);
                storage_space += needed_space;
            }
        }

        let storage_space = storage_space as usize;
        let tcb_head_size = 704;
        let total_size = storage_space + tcb_head_size;

        // allocate the whole capacity upfront so the vector doesn't 
        // get resized, and `tcb_addr` doesn't get invalidated
        let mut block = Vec::with_capacity(total_size);
        let tcb_addr = delf::Addr(block.as_ptr() as u64 + storage_space as u64);
        for _ in 0..storage_space {
            // for now, zero out storage
            block.push(0u8);
        }

        // build a "somewhat fake" tcbhead structure
        block.extend(&tcb_addr.0.to_le_bytes()); // tcb
        block.extend(&0_u64.to_le_bytes()); // dtv
        block.extend(&tcb_addr.0.to_le_bytes()); // thread pointer
        block.extend(&0_u32.to_le_bytes()); // multiple_threads
        block.extend(&0_u32.to_le_bytes()); // gscope_flag
        block.extend(&0_u64.to_le_bytes()); // sysinfo
        block.extend(&0xDEADBEEF_u64.to_le_bytes()); // stack guard
        block.extend(&0xFEEDFACE_u64.to_le_bytes()); // pointer guard
        while block.len() < block.capacity() {
            // just pad out with zeros
            block.push(0u8);
        }

        let tls = TLS {
            offsets,
            block: block,
            tcb_addr,
        };

        Process {
            state: TLSAllocated {
                loader: self.state.loader,
                tls,
            },
        }
    }
}

impl Process<TLSAllocated> {
    pub fn apply_relocations(self) -> Result<Process<Relocated>, RelocationError> {
        let rels: Vec<ObjectRel> = self
            .state
            .loader
            .objects
            .iter()
            .rev()
            .map(|obj| {
                obj.relocations.iter().map(move |rel| ObjectRel { obj, rel })
            })
            .flatten()
            .collect();

        for rel in rels {
            self.apply_relocation(rel)?;
        }

        Ok(Process {
            state: Relocated {
                loader: self.state.loader,
                tls: self.state.tls,
            }
        })
    }

    fn apply_relocation(&self, objrel: ObjectRel) -> Result<(), RelocationError> {
        use delf::RelType as RT;

        let ObjectRel { obj, rel } = objrel;
        let wanted = ObjectSym {
            obj,
            sym: &obj.syms[rel.sym as usize],
        };
        let ignore_self = matches!(rel.reloc_type, RT::Copy);

        let found: ResolvedSym = match rel.sym {
            0 => ResolvedSym::Undefined,
            _ => match self.lookup_symbol(&wanted, ignore_self) {
                ResolvedSym::Undefined => {
                    match wanted.sym.sym.bind {
                        delf::SymBind::Weak => ResolvedSym::Undefined, // weak symbols can be undefined 
                        _ => return Err(RelocationError::UndefinedSymbol(wanted.sym.clone())),
                    }
                },
                x => x,
            }
        };

        match rel.reloc_type {
            RT::_64 => unsafe {
                objrel.addr().set(found.value() + rel.addend);
            },
            RT::Copy => unsafe {
                objrel.addr().write(found.value().as_slice(found.size()));
            },
            RT::Relative => unsafe {
                objrel.addr().set(obj.base + rel.addend);
            },
            RT::IRelative => unsafe {
                type Selector = unsafe extern "C" fn() -> delf::Addr;
                let selector: Selector = std::mem::transmute(obj.base + rel.addend);
                objrel.addr().set(selector());
            },
            RT::GlobDat | RT::JumpSlot => unsafe {
                objrel.addr().set(found.value());
            },
            RT::TPOff64 => unsafe {
                if let ResolvedSym::Defined(sym) = found {
                    let obj_offset = self
                        .state
                        .tls
                        .offsets
                        .get(&sym.obj.base)
                        .unwrap_or_else(|| panic!("No thread-local storage allocated for object {:?}", sym.obj.file));

                    let obj_offset = -(obj_offset.0 as i64);
                    let offset = obj_offset + sym.sym.sym.value.0 as i64 + objrel.rel.addend.0 as i64;
                    objrel.addr().set(offset);
                }
            },
            _ => {
                return Err(RelocationError::UnimplementedRelocation(
                    obj.path.clone(),
                    rel.reloc_type,
                ))
            }
        }

        Ok(())
    }
}

impl Process<Relocated> {
    pub fn initialize_tls(self) -> Process<TLSInitialized> {
        let tls = &self.state.tls;

        for obj in &self.state.loader.objects {
            if let Some(ph) = obj.file.segment_of_type(delf::SegmentType::TLS) {
                if let Some(offset) = tls.offsets.get(&obj.base).cloned() {
                    unsafe {
                        (tls.tcb_addr - offset).write(
                            (ph.vaddr + obj.base).as_slice(ph.filesz.into())
                        );
                    }
                }
            }
        }

        Process {
            state: TLSInitialized {
                loader: self.state.loader,
                tls: self.state.tls,
            },
        }
    }
}

impl Process<TLSInitialized> {
    pub fn adjust_protections(self) -> Result<Process<Protected>, region::Error> {
        use region::{protect, Protection};
        use delf::SegmentFlag as SF;

        for obj in &self.state.loader.objects {
            for seg in &obj.loaded_segments {
                let mut prot = Protection::NONE;
                for flag in seg.flags.iter() {
                    prot |= match flag {
                        SF::Read => Protection::READ,
                        SF::Write => Protection::WRITE,
                        SF::Execute => Protection::EXECUTE,
                    }
                }
                
                unsafe {
                    protect(seg.map.data(), seg.map.len(), prot)?;
                }
            }
        }

        Ok(Process{
            state: Protected {
                loader: self.state.loader,
                tls: self.state.tls,
            }
        })
    }
}

impl<S: ProcessState> Process<S> {
    fn lookup_symbol(
        &self,
        wanted: &ObjectSym,
        ignore_self: bool,
    ) -> ResolvedSym {
        for obj in &self.state.loader().objects {
            if ignore_self && std::ptr::eq(wanted.obj, obj) {
                continue;
            }

            if let Some(syms) = obj.sym_map.get_vec(&wanted.sym.name) {
                if let Some(sym) = syms.iter().find(|s| s.sym.section_index.is_undef() == false) {
                    return ResolvedSym::Defined(ObjectSym{ obj, sym })
                }
            }
        }

        ResolvedSym::Undefined
    }
}

fn convex_hull(a: Range<delf::Addr>, b: Range<delf::Addr>) -> Range<delf::Addr> {
    (min(a.start, b.start))..(max(a.end, b.end))
}