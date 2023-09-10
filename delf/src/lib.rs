mod parse;
mod hex_dump;
mod addr;
mod program_header;
mod section_header;
mod rela;
mod symb;

use derive_try_from_primitive::TryFromPrimitive;

pub use addr::Addr;
pub use hex_dump::HexDump;
pub use program_header::{
    SegmentType,
    SegmentFlag,
    DynamicTag,
    DynamicEntry,
    SegmentContents,
    ProgramHeader,
};
pub use section_header::{
    SectionType,
    SectionHeader,
};
pub use symb::{
    Sym,
    SymBind,
    SymType,
};
pub use rela::{
    Rela,
    RelType,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Type {
    None = 0x0,
    Rel = 0x1,
    Exec = 0x2,
    Dyn = 0x3,
    Core = 0x4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Machine {
    X86 = 0x03,
    X86_64 = 0x3e,
}

impl_parse_for_enum!(Type, le_u16);
impl_parse_for_enum!(Machine, le_u16);

#[derive(thiserror::Error, Debug)]
pub enum ReadSymsError {
    #[error("Parsing error: {0}")]
    ParsingError(String),
}

#[derive(thiserror::Error, Debug)]
pub enum ReadRelaError {
    #[error("{0}")]
    DynamicEntryNotFound(#[from] GetDynamicEntryError),
    #[error("Rela table segment not found")]
    RelaSegmentNotFound,
    #[error("Parsing error: {0}")]
    ParsingError(String),
}

#[derive(thiserror::Error, Debug)]
pub enum GetDynamicEntryError {
    #[error("Dynamic entry {0:?} not found")]
    NotFound(DynamicTag),
}

#[derive(Debug)]
pub struct File {
    pub r#type: Type,
    pub machine: Machine,
    pub entry_point: Addr,
    pub program_headers: Vec<ProgramHeader>,
    pub section_headers: Vec<SectionHeader>,
    pub shstrndx: usize,
    pub contents: Vec<u8>,
}

impl File {
    // 0x7f, 'E', 'L', 'F'
    const MAGIC: &'static [u8] = &[0x7f, 0x45, 0x4c, 0x46];

    #[allow(unused_variables)]
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{
            bytes::complete::{tag, take},
            error::context,
            sequence::tuple,
            combinator::verify,
            combinator::map,
            number::complete::le_u32,
            number::complete::le_u16,
        };
        let u16_as_usize = map(le_u16, |x| x as usize);

        let full_input = i;

        let (i, _) = tuple((
            context("Magic", tag(Self::MAGIC)),
            context("Class", tag(&[0x2])),      // 64 bit
            context("Endianness", tag(&[0x1])), // little
            context("Version", tag(&[0x1])),
            context("OS ABI", nom::branch::alt((tag(&[0x0]), tag(&[0x3])))),
            context("Padding", take(8_usize)),
        ))(i)?;

        let (i, (r#type, machine)) = tuple((Type::parse, Machine::parse))(i)?;
        let (i, _) = context("Version (bis)", verify(le_u32, |&x| x == 1))(i)?;
        let (i, entry_point) = Addr::parse(i)?;
        let (i, (ph_offset, sh_offset)) = tuple((Addr::parse, Addr::parse))(i)?;
        let (i, (flags, hdr_size)) = tuple((le_u32, le_u16))(i)?;
        let (i, (ph_entsize, ph_count)) = tuple((&u16_as_usize, &u16_as_usize))(i)?;
        let (i, (sh_entsize, sh_count, sh_nidx)) = tuple((&u16_as_usize, &u16_as_usize, &u16_as_usize))(i)?;

        let ph_slices = (&full_input[ph_offset.into()..]).chunks(ph_entsize);
        let mut program_headers = Vec::new();
        for ph_slice in ph_slices.take(ph_count) {
            let (_, ph) = ProgramHeader::parse(full_input, ph_slice)?;
            program_headers.push(ph);
        }

        let sh_slices = (&full_input[sh_offset.into()..]).chunks(sh_entsize);
        let mut section_headers = Vec::new();
        for sh_slice in sh_slices.take(sh_count) {
            let (_, sh) = SectionHeader::parse(sh_slice)?;
            section_headers.push(sh);
        }

        let res = Self {
            r#type,
            machine,
            entry_point,
            program_headers,
            section_headers,
            shstrndx: sh_nidx as _,
            contents: full_input.into(),
        };
        Ok((i, res))
    }

    pub fn parse_or_print_error(i: parse::Input) -> Option<Self> {
        match Self::parse(i) {
            Ok((_, file)) => Some(file),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                eprintln!("Parsing failed:");
                for (input, err) in err.errors {
                    use nom::Offset;
                    let offset = i.offset(input);
                    eprintln!("{:?} at position {}:", err, offset);
                    eprintln!("{:>08x}: {:?}", offset, HexDump(input));
                }
                None
            }
            Err(_) => panic!("unexpected nom error"),
        }
    }

    /// Returns the first segment of a given type
    pub fn segment_of_type(&self, r#type: SegmentType) -> Option<&ProgramHeader> {
        self.program_headers.iter().find(|ph| ph.r#type == r#type)
    }

    /// Returns the first section of a given type
    pub fn section_of_type(&self, r#type: SectionType) -> Option<&SectionHeader> {
        self.section_headers.iter().find(|sh| sh.r#type == r#type)
    }

    /// Attempts to find the Dynamic segment and return its entries as a slice
    pub fn dynamic_table(&self) -> Option<&[DynamicEntry]> {
        match self.segment_of_type(SegmentType::Dynamic) {
            Some(ProgramHeader {
                contents: SegmentContents::Dynamic(entries),
                ..
            }) => Some(entries),
            _ => None,
        }
    }

    /// Returns an iterator of the values of all dynamic entries with the given tag.
    pub fn dynamic_entries(&self, tag: DynamicTag) -> impl Iterator<Item = Addr> + '_ {
        self.dynamic_table()
            .unwrap_or_default()
            .iter()
            .filter(move |e| e.tag == tag)
            .map(|e| e.addr)
    }

    /// Returns the value of the first dynamic entry with the given tag, or None
    pub fn dynamic_entry(&self, tag: DynamicTag) -> Option<Addr> {
        self.dynamic_entries(tag).next()
    }

    /// Returns the value of the first dynamic entry with the given tag, or an error
    pub fn get_dynamic_entry(&self, tag: DynamicTag) -> Result<Addr, GetDynamicEntryError> {
        self.dynamic_entry(tag)
            .ok_or(GetDynamicEntryError::NotFound(tag))
    }
    
    /// Attempts to find a Load segment whose memory range contains the given virtual address
    pub fn segment_containing(&self, addr: Addr) -> Option<&ProgramHeader> {
        self.program_headers
        .iter()
        .filter(|ph| ph.r#type == SegmentType::Load)
        .find(|ph| ph.mem_range().contains(&addr))
    }

    fn file_slice(&self, range: std::ops::Range<Addr>) -> &[u8] {
        &self.contents[range.start.into()..range.end.into()]
    }

    /// Returns a slice of the file corresponding to the given section
    pub fn section_slice(&self, section: &SectionHeader) -> &[u8] {
        self.file_slice(section.file_range())
    }

    /// Returns a slice of the file corresponding to the given segment
    pub fn segment_slice(&self, segment: &ProgramHeader) -> &[u8] {
        self.file_slice(segment.file_range())
    }

    /// Returns a slice of the file, indexed by virtual addresses
    pub fn mem_slice(&self, addr: Addr, len: usize) -> Option<&[u8]> {
        self.segment_containing(addr)
            .map(|seg| {
                let start = (addr - seg.mem_range().start).into();
                &self.segment_slice(seg)[start..start + len]
            })
    }

    /// Returns an iterator of string values (u8 slices) of
    /// dynamic entries for the given tag
    pub fn dynamic_entry_strings(&self, tag: DynamicTag) -> impl Iterator<Item = &[u8]> + '_ {
        self.dynamic_entries(tag)
            .map(move |addr| self.dynstr_entry(addr))
    }
    
    /// Read relocation entries from the table pointed to by `DynamicTag::Rela`
    pub fn read_rela_entries(&self) -> Result<Vec<Rela>, ReadRelaError> {
        self.read_relocations(DynamicTag::Rela, DynamicTag::RelaSz)
    }
    
    /// Read relocation entries from the table pointed to by `DynamicTag::JmpRel`
    pub fn read_jmp_rel_entries(&self) -> Result<Vec<Rela>, ReadRelaError> {
        self.read_relocations(DynamicTag::JmpRel, DynamicTag::PltRelSz)
    }

    fn read_relocations(
        &self,
        addr_tag: DynamicTag,
        size_tag: DynamicTag,
    ) -> Result <Vec<Rela>, ReadRelaError> {
        match self.dynamic_entry(addr_tag) {
            None => Ok(vec![]),
            Some(addr) => {
                let len = self.get_dynamic_entry(size_tag)?;
        
                let i = self.mem_slice(addr, len.into()).ok_or(ReadRelaError::RelaSegmentNotFound)?;
                let i = &i[..len.into()];
                let n = (len.0 as usize) / Rela::SIZE; 
                use nom::multi::many_m_n;
        
                match many_m_n(n, n, Rela::parse)(i) {
                    Ok((_, rela_entries)) => Ok(rela_entries),
                    Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                        Err(ReadRelaError::ParsingError(format!("{:?}", err)))
                    }
                    // we don't use any "streaming" parsers, so `nom::Err::Incomplete` seems unlikely
                    _ => unreachable!(),
                }
            }
        }
    }

    /// Read symbols from the ".dynsym" section (loader view)
    pub fn read_dynsym_entries(&self) -> Result<Vec<Sym>, ReadSymsError> {
        self.read_symbol_table(SectionType::DynSym)
    }

    /// Read symbols from the ".symtab" section (linker view)
    pub fn read_symtab_entries(&self) -> Result<Vec<Sym>, ReadSymsError> {
        self.read_symbol_table(SectionType::SymTab)
    }
    
    /// Returns a null-terminated "string" from the ".shstrtab" section as an u8 slice
    pub fn shstrtab_entry(&self, offset: Addr) -> &[u8] {
        let section = &self.section_headers[self.shstrndx];
        let slice = &self.section_slice(section)[offset.into()..];
        slice.split(|&c| c == 0).next().unwrap_or_default()
    }

    /// Get a section by name
    pub fn section_by_name(&self, name: &[u8]) -> Option<&SectionHeader> {
        self.section_headers
            .iter()
            .find(|sh| self.shstrtab_entry(sh.name) == name)
    }

    /// Returns an entry from a string table contained in the section with a given name
    fn string_table_entry(&self, name: &[u8], offset: Addr) -> &[u8] {
        self.section_by_name(name)
            .map(|section| {
                let slice = &self.section_slice(section)[offset.into()..];
                slice.split(|&c| c == 0).next().unwrap_or_default()
            })
            .unwrap_or_default()
    }

    /// Returns a null-terminated "string" from the ".strtab" section as an u8 slice
    pub fn strtab_entry(&self, offset: Addr) -> &[u8] {
        self.string_table_entry(b".strtab", offset)
    }

    /// Returns a null-terminated "string" from the ".dynstr" section as an u8 slice
    pub fn dynstr_entry(&self, offset: Addr) -> &[u8] {
        self.string_table_entry(b".dynstr", offset)
    }

    /// Read symbols from the given section (internal)
    fn read_symbol_table(&self, section_type: SectionType) -> Result<Vec<Sym>, ReadSymsError> {
        let section = match self.section_of_type(section_type) {
            Some(section) => section,
            None => return Ok(vec![]),
        };

        let i = self.section_slice(section);
        let n = (section.size.0 / section.entsize.0) as usize;
        use nom::multi::many_m_n;

        match many_m_n(n, n, Sym::parse)(i) {
            Ok((_, syms)) => Ok(syms),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                Err(ReadSymsError::ParsingError(format!("{:?}", err)))
            }
            _ => unreachable!(),
        }
    }
}