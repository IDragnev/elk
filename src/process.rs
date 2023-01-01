use mmap::{
    MemoryMap,
    MapOption,
};
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
};
use enumflags2::BitFlags;

#[derive(CustomDebug)]
pub struct Segment {
    #[debug(skip)]
    pub map: MemoryMap,
    pub padding: delf::Addr,
    pub flags: BitFlags<delf::SegmentFlag>,
}

#[derive(CustomDebug)]
pub struct Object {
    pub path: PathBuf,
    pub base: delf::Addr,
    pub mem_range: Range<delf::Addr>,
    pub maps: Vec<Segment>,
    #[debug(skip)]
    pub file: delf::File,
    #[debug(skip)]
    pub syms: Vec<delf::Sym>,
}

#[derive(thiserror::Error, Debug)]
pub enum LoadError {
    #[error("ELF object not found: {0}")]
    NotFound(String),
    #[error("And invalid or unsupported path was encountered")]
    InvalidPath(PathBuf),
    #[error("I/O error: {0}")]
    IO(PathBuf, std::io::Error),
    #[error("ELF object could not be parsed: {0}")]
    ParseError(PathBuf),
    #[error("ELF object has no load segments")]
    NoLoadSegments,
    #[error("ELF object could not be mapped in memory: {0}")]
    MapError(#[from] mmap::MapError),   
    #[error("Could not read symbols from ELF object: {0}")]
    ReadSymsError(#[from] delf::ReadSymsError),   
}

#[derive(thiserror::Error, Debug)]
pub enum RelocationError {
    #[error("Unknown relocation: {0}")]
    UnknownRelocation(u32),
    #[error("Unimplemented relocation: {0:?}")]
    UnimplementedRelocation(delf::KnownRelType),
    #[error("Unknown symbol number: {0}")]
    UnknownSymbolNumber(u32),
    #[error("Undefined symbol: {0}")]
    UndefinedSymbol(String),
}

#[derive(Debug)]
pub struct Process {
    pub objects: Vec<Object>,
    pub objects_by_path: HashMap<PathBuf, usize>,
    pub search_path: Vec<PathBuf>,
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

impl Object {
    pub fn sym_name(&self, index: u32) -> Result<String, RelocationError> {
        self.file
            .get_string(self.syms[index as usize].name)
            .map_err(|_| RelocationError::UnknownSymbolNumber(index))
    }
}

impl Process {
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
            objects_by_path: HashMap::new(),
            search_path: vec!["/usr/lib".into()],
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
                .map(|index| &self.objects[index].file)
                .flat_map(|file| file.dynamic_entry_strings(delf::DynamicTag::Needed))
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
            let rpath = rpath.replace("$ORIGIN", &origin);
            println!("Found RPATH entry {:?}", rpath);

            self.search_path.push(PathBuf::from(rpath));
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

        let maps = load_segments()
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
                            MapOption::MapFd(fs_file.as_raw_fd()),
                            MapOption::MapOffset(offset.into()),
                            MapOption::MapAddr(unsafe { (base + vaddr).as_ptr() }),
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
                    map,
                    padding,
                    flags: ph.flags,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let syms = file.read_syms()?;

        let obj = Object {
            path: path.clone(),
            base,
            maps,
            file,
            mem_range,
            syms,
        };
        let index = self.objects.len();
        self.objects.push(obj);
        self.objects_by_path.insert(path, index);

        Ok(index)
    }

    pub fn get_object(&mut self, name: &str) -> Result<GetResult, LoadError> {
        let path = self.object_path(name)?;
        self.objects_by_path
            .get(&path)
            .map(|&index| Ok(GetResult::Cached(index)))
            .unwrap_or_else(|| self.load_object(path).map(GetResult::Fresh))
    }

    pub fn object_path(&self, name: &str) -> Result<PathBuf, LoadError> {
        self.search_path
            .iter()
            .filter_map(|prefix| prefix.join(name).canonicalize().ok())
            .find(|path| path.exists())
            .ok_or_else(|| LoadError::NotFound(name.into()))
    }

    pub fn apply_relocations(&self) -> Result<(), RelocationError> {
        for obj in self.objects.iter().rev() {
            println!("Applying relocations for {:?}", obj.path);

            match obj.file.read_rela_entries() {
                Ok(rels) => {
                    for rel in rels {
                        println!("Found {:?}", rel);

                        match rel.reloc_type {
                            delf::RelType::Known(t) => match t {
                                delf::KnownRelType::_64 => {
                                    let name = obj.sym_name(rel.sym)?;
                                    let (lib, sym) = self
                                        .lookup_symbol(&name, None)?
                                        .ok_or(RelocationError::UndefinedSymbol(name))?;

                                    let mut offset = obj.base + rel.offset;
                                    let value = sym.value + lib.base + rel.addend;

                                    unsafe {
                                        let ptr: *mut u64 = offset.as_mut_ptr();
                                        *ptr = value.0;
                                    }
                                },
                                delf::KnownRelType::Copy => {
                                    let name = obj.sym_name(rel.sym)?;
                                    let obj_to_ignore = Some(obj);
                                    let (lib, sym) = self
                                        .lookup_symbol(&name, obj_to_ignore)?
                                        .ok_or_else(|| RelocationError::UndefinedSymbol(name))?;

                                    unsafe {
                                        let src = (sym.value + lib.base).as_ptr();
                                        let dst = (rel.offset + obj.base).as_mut_ptr();
                                        std::ptr::copy_nonoverlapping::<u8>(
                                            src,
                                            dst,
                                            sym.size as usize,
                                        );
                                    }
                                },
                                _ => return Err(RelocationError::UnimplementedRelocation(t)),
                            },
                            delf::RelType::Unknown(num) => {
                                return Err(RelocationError::UnknownRelocation(num))
                            }
                        }
                    }
                },
                Err(e) => println!("Nevermind: {:?}", e),
            }
        }

        Ok(())
    }

    pub fn adjust_protections(&self) -> Result<(), region::Error> {
        use region::{protect, Protection};
        use delf::SegmentFlag as SF;

        for obj in &self.objects {
            for seg in &obj.maps {
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

        Ok(())
    }

    pub fn lookup_symbol(
        &self,
        name: &str,
        ignore: Option<&Object>,
    ) -> Result<Option<(&Object, &delf::Sym)>, RelocationError> {
        for obj in &self.objects {
            if let Some(ignored) = ignore {
                if std::ptr::eq(ignored, obj) {
                    continue;
                }
            }

            for (i, sym) in obj.syms.iter().enumerate() {
                if obj.sym_name(i as u32)? == name {
                    return Ok(Some((obj, sym)));
                }
            }
        }
        Ok(None)
    }
}

fn convex_hull(a: Range<delf::Addr>, b: Range<delf::Addr>) -> Range<delf::Addr> {
    (min(a.start, b.start))..(max(a.end, b.end))
}