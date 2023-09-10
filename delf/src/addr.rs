use derive_more as dvmr;
use std::fmt;
use crate::parse;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, dvmr::Add, dvmr::Sub, Hash)]
#[repr(transparent)]
pub struct Addr(pub u64);

impl Into<u64> for Addr {
    fn into(self) -> u64 {
        self.0
    }
}

impl Into<usize> for Addr {
    fn into(self) -> usize {
        self.0 as usize
    }
}

impl From<u64> for Addr {
    fn from(x: u64) -> Self {
        Self(x)
    }
}

impl Addr {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{combinator::map, number::complete::le_u64};
        map(le_u64, From::from)(i)
    }

    /// # Safety
    ///
    /// This can create dangling pointers and all sorts of eldritch errors.
    pub fn as_ptr<T>(&self) -> *const T {
        self.0 as *const T
    }

    /// # Safety
    ///
    /// This can create dangling pointers and all sorts of eldritch errors.
    pub fn as_mut_ptr<T>(&mut self) -> *mut T {
        self.0 as *mut T
    }

    pub unsafe fn as_slice<T>(&self, len: usize) -> &[T] {
        std::slice::from_raw_parts(self.as_ptr(), len)
    }

    pub unsafe fn as_mut_slice<T>(&mut self, len: usize) -> &mut [T] {
        std::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }

    pub unsafe fn write(&mut self, src: &[u8]) {
        std::ptr::copy_nonoverlapping(src.as_ptr(), self.as_mut_ptr(), src.len());
    }

    pub unsafe fn set<T>(&mut self, src: T) {
        *self.as_mut_ptr() = src;
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}