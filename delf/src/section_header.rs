use derive_try_from_primitive::TryFromPrimitive;
use crate::{
    addr::Addr,
    parse,
    impl_parse_for_enum,
};
use std::{
    ops::{
        Range,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum SectionType {
    Null = 0,
    ProgBits = 1,
    SymTab = 2,
    StrTab = 3,
    Rela = 4,
    Hash = 5,
    Dynamic = 6,
    Note = 7,
    NoBits = 8,
    Rel = 9,
    ShLib = 10,
    DynSym = 11,
    InitArray = 14,
    FiniArray = 15,
    PreinitArray = 16,
    Group = 17,
    SymTabShndx = 18,
    Num = 19,
    GnuAttributes = 0x6ffffff5,
    GnuHash = 0x6ffffff6,
    GnuLiblist = 0x6ffffff7,
    Checksum = 0x6ffffff8,
    GnuVerdef = 0x6ffffffd,
    GnuVerneed = 0x6ffffffe,
    GnuVersym = 0x6fffffff,
    X8664Unwind = 0x70000001,
}

impl_parse_for_enum!(SectionType, le_u32);

#[derive(Debug)]
pub struct SectionHeader {
    pub name: Addr,
    pub r#type: SectionType,
    pub flags: u64,
    pub addr: Addr,
    pub file_offset: Addr,
    pub size: Addr,
    pub link: u32,
    pub info: u32,
    pub addralign: Addr,
    pub entsize: Addr,
}

impl SectionHeader {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{
            combinator::map,
            number::complete::{le_u32, le_u64},
            sequence::tuple,
        };
        let (i, (name, r#type, flags, addr, file_offset, size, link, info, addralign, entsize)) =
            tuple((
                map(le_u32, |x| Addr(x as u64)),
                SectionType::parse,
                le_u64,
                Addr::parse,
                Addr::parse,
                Addr::parse,
                le_u32,
                le_u32,
                Addr::parse,
                Addr::parse,
            ))(i)?;
        let res = Self {
            name,
            r#type,
            flags,
            addr,
            file_offset,
            size,
            link,
            info,
            addralign,
            entsize,
        };
        Ok((i, res))
    }

    /**
     * File range where the section is stored
     */
    pub fn file_range(&self) -> Range<Addr> {
        self.file_offset..self.file_offset + self.size
    }

    /**
     * Memory range where the section is mapped
     */
    pub fn mem_range(&self) -> Range<Addr> {
        self.addr..self.addr + self.size
    }
}