use derive_try_from_primitive::TryFromPrimitive;
use crate::{
    parse,
    addr::Addr,
    impl_parse_for_bitenum,
};

#[derive(Debug, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum SymBind {
    Local = 0,
    Global = 1,
    Weak = 2,
}

#[derive(Debug, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum SymType {
    None = 0,
    Object = 1,
    Func = 2,
    Section = 3,
    File = 4,
    TLS = 6,
    IFunc = 10,
}

impl_parse_for_bitenum!(SymBind, 4_usize);
impl_parse_for_bitenum!(SymType, 4_usize);

#[derive(Clone, Copy)]
pub struct SectionIndex(pub u16);

impl SectionIndex {
    pub fn is_undef(&self) -> bool {
        self.0 == 0
    }

    pub fn is_special(&self) -> bool {
        self.0 >= 0xff00
    }

    pub fn get(&self) -> Option<usize> {
        if self.is_undef() || self.is_special() {
            None
        } else {
            Some(self.0 as usize)
        }
    }
}

impl std::fmt::Debug for SectionIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.is_special() {
            write!(f, "Special({:04x})", self.0)
        } else if self.is_undef() {
            write!(f, "Undef")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

#[derive(Debug, Clone)]
pub struct Sym {
    pub name: Addr,
    pub bind: SymBind,
    pub sym_type: SymType,
    pub section_index: SectionIndex,
    pub value: Addr,
    pub size: u64,
}

impl Sym {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{
            bits::bits,
            combinator::map,
            number::complete::{le_u16, le_u32, le_u64, le_u8},
            sequence::tuple,
        };

        let (i, (name, (bind, sym_type), _reserved, section_index, value, size)) = tuple((
            map(le_u32, |x| Addr(x as u64)),
            bits(tuple((SymBind::parse, SymType::parse))),
            le_u8,
            map(le_u16, SectionIndex),
            Addr::parse,
            le_u64,
        ))(i)?;

        let res = Self {
            name,
            bind,
            sym_type,
            section_index,
            value,
            size,
        };
        Ok((i, res))
    }
}