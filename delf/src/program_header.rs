use crate::{
    impl_parse_for_enum,
    impl_parse_for_enumflags,
    addr::Addr,
    parse,
};
use derive_try_from_primitive::TryFromPrimitive;
use enumflags2::*;
use std::{
    ops::Range,
    fmt,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum SegmentType {
    Null = 0x0,
    Load = 0x1,
    Dynamic = 0x2,
    Interp = 0x3,
    Note = 0x4,
    ShLib = 0x5,
    PHdr = 0x6,
    TLS = 0x7,
    LoOS = 0x6000_0000,
    HiOS = 0x6FFF_FFFF,
    LoProc = 0x7000_0000,
    HiProc = 0x7FFF_FFFF,
    GnuEhFrame = 0x6474_E550,
    GnuStack = 0x6474_E551,
    GnuRelRo = 0x6474_E552,
    GnuProperty = 0x6474_E553,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BitFlags)]
#[repr(u32)]
pub enum SegmentFlag {
    Execute = 0x1,
    Write = 0x2,
    Read = 0x4,
}

impl_parse_for_enum!(SegmentType, le_u32);
impl_parse_for_enumflags!(SegmentFlag, le_u32);

#[derive(Debug, TryFromPrimitive, PartialEq, Eq, Copy, Clone)]
#[repr(u64)]
pub enum DynamicTag {
    Null = 0,
    Needed = 1,
    PltRelSz = 2,
    PltGot = 3,
    Hash = 4,
    StrTab = 5,
    SymTab = 6,
    Rela = 7,
    RelaSz = 8,
    RelaEnt = 9,
    StrSz = 10,
    SymEnt = 11,
    Init = 12,
    Fini = 13,
    SoName = 14,
    RPath = 15,
    Symbolic = 16,
    Rel = 17,
    RelSz = 18,
    RelEnt = 19,
    PltRel = 20,
    Debug = 21,
    TextRel = 22,
    JmpRel = 23,
    BindNow = 24,
    InitArray = 25,
    FiniArray = 26,
    InitArraySz = 27,
    FiniArraySz = 28,
    RunPath = 29,
    Flags = 30,
    LoProc = 0x70000000,
    HiProc = 0x7fffffff,
    GnuHash = 0x6ffffef5,
    VerSym = 0x6ffffff0,
    RelACount = 0x6ffffff9,
    Flags1 = 0x6ffffffb,
    VerDef = 0x6ffffffc,
    VerDefNum = 0x6ffffffd,
    VerNeed = 0x6ffffffe,
    VerNeedNum = 0x6fffffff,
}

impl_parse_for_enum!(DynamicTag, le_u64);

#[derive(Debug)]
pub struct DynamicEntry {
    pub tag: DynamicTag,
    pub addr: Addr,
}

impl DynamicEntry {
    fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::sequence::tuple;

        let (i, (tag, addr)) = tuple((DynamicTag::parse, Addr::parse))(i)?;
        Ok((i, Self { tag, addr }))
    }
}

#[derive(Debug)]
pub enum SegmentContents {
    Dynamic(Vec<DynamicEntry>),
    Unknown,
}

pub struct ProgramHeader {
    pub r#type: SegmentType,
    pub flags: BitFlags<SegmentFlag>,
    pub offset: Addr,
    pub vaddr: Addr,
    pub paddr: Addr,
    pub filesz: Addr,
    pub memsz: Addr,
    pub align: Addr,
    pub contents: SegmentContents,
}

impl ProgramHeader {
    /**
     * File range where the segment is stored
     */
    pub fn file_range(&self) -> Range<Addr> {
        self.offset..self.offset + self.filesz
    }

    /**
     * Memory range where the segment is mapped
     */
    pub fn mem_range(&self) -> Range<Addr> {
        self.vaddr..self.vaddr + self.memsz
    }

    pub fn parse<'a>(full_input: parse::Input<'a>, i: parse::Input<'a>) -> parse::Result<'a, Self> {
        use nom::{
            sequence::tuple,
            combinator::{map, verify},
            multi::many_till,
        };

        let (i, (r#type, flags)) = tuple((SegmentType::parse, SegmentFlag::parse))(i)?;

        let ap = Addr::parse;
        let (i, (offset, vaddr, paddr, filesz, memsz, align)) = tuple((ap, ap, ap, ap, ap, ap))(i)?;

        let slice = &full_input[offset.into()..][..filesz.into()];
        let (_, contents) = match r#type {
            SegmentType::Dynamic => {
                map(
                    many_till(
                        DynamicEntry::parse,
                        verify(DynamicEntry::parse, |e| e.tag == DynamicTag::Null),
                    ),
                    |(entries, _last)| SegmentContents::Dynamic(entries),
                )(slice)?
            },
            _ => (slice, SegmentContents::Unknown),
        };

        let res = Self {
            r#type,
            flags,
            offset,
            vaddr,
            paddr,
            filesz,
            memsz,
            align,
            contents,
        };
        Ok((i, res))
    }
}

impl fmt::Debug for ProgramHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let flags = &[
            (SegmentFlag::Read, "R"),
            (SegmentFlag::Write, "W"),
            (SegmentFlag::Execute, "X"),
        ]
        .iter()
        .map(|&(b, s)| { if self.flags.contains(b) { s } else { "-" } })
        .collect::<Vec<_>>()
        .join("");

        write!(
            f,
            "file {:?} | mem {:?} | align {:?} | {} | {:?}",
            self.file_range(),
            self.mem_range(),
            self.align,
            flags,
            self.r#type,
        )
    }
}
