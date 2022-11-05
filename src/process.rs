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
        let mem_map = MemoryMap::new(mem_size, &[])?;
        let base = delf::Addr(mem_map.data() as _) - mem_range.start;

        let maps = load_segments().filter_map(|ph| {
            if ph.memsz.0 > 0 {
                use std::os::unix::io::AsRawFd;

                let vaddr = delf::Addr(ph.vaddr.0 & !0xFFF);
                let padding = ph.vaddr - vaddr;
                let offset = ph.offset - padding;
                let memsz = ph.memsz + padding;
                println!("> {:#?}", ph);
                println!(
                    "< file {:#?} | mem {:#?}",
                    offset..(offset + memsz),
                    vaddr..(vaddr + memsz)
                );

                let map_res = MemoryMap::new(
                        memsz.into(),
                        &[
                            MapOption::MapReadable,
                            MapOption::MapWritable,
                            MapOption::MapFd(fs_file.as_raw_fd()),
                            MapOption::MapOffset(offset.into()),
                            MapOption::MapAddr(unsafe { (base + vaddr).as_ptr() }),
                        ],
                    );

                Some(map_res.map(|map| Segment {
                    map,
                    padding,
                    flags: ph.flags,
                }))
            } else {
                None
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

        let obj = Object {
            path: path.clone(),
            base,
            maps,
            file,
            mem_range,
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
}

fn convex_hull(a: Range<delf::Addr>, b: Range<delf::Addr>) -> Range<delf::Addr> {
    (min(a.start, b.start))..(max(a.end, b.end))
}