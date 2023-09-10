use crate::{
    addr::Addr,
    parse,
    impl_parse_for_enum,
};
use derive_try_from_primitive::TryFromPrimitive;

#[derive(Debug, TryFromPrimitive, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RelType {
    _64 = 1,
    Copy = 5,
    GlobDat = 6,
    JumpSlot = 7,
    Relative = 8,
    TPOff64 = 18,
    IRelative = 37,
}

impl_parse_for_enum!(RelType, le_u32);

#[derive(Debug)]
pub struct Rela {
    pub offset: Addr,
    pub reloc_type: RelType,
    pub sym: u32,
    pub addend: Addr,
}

impl Rela {
    pub const SIZE: usize = 24;

    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{combinator::map, number::complete::le_u32, sequence::tuple};
        map(
            tuple((Addr::parse, RelType::parse, le_u32, Addr::parse)),
            |(offset, reloc_type, sym, addend)| Rela {
                offset,
                reloc_type,
                sym,
                addend,
            },
        )(i)
    }
}