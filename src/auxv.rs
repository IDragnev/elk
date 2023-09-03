#[derive(Debug, Clone, Copy)]
#[repr(u64)]
pub enum AuxType {
    /// End of vector
    Null = 0,
    /// Entry should be ignored
    Ignore = 1,
    /// File descriptor of program
    ExecFd = 2,
    /// Program headers for program
    PHdr = 3,
    /// Size of program header entry
    PhEnt = 4,
    /// Number of program headers
    PhNum = 5,
    /// System page size
    PageSz = 6,
    /// Base address of interpreter
    Base = 7,
    /// Flags
    Flags = 8,
    /// Entry point of program
    Entry = 9,
    /// Program is not ELF
    NotElf = 10,
    /// Real uid
    Uid = 11,
    /// Effective uid
    EUid = 12,
    /// Real gid
    Gid = 13,
    /// Effective gid
    EGid = 14,
    /// String identifying CPU for optimizations
    Platform = 15,
    /// Arch-dependent hints at CPU capabilities
    HwCap = 16,
    /// Frequency at which times() increments
    ClkTck = 17,
    /// Secure mode boolean
    Secure = 23,
    /// String identifying real platform, may differ from Platform
    BasePlatform = 24,
    /// Address of 16 random bytes
    Random = 25,
    // Extension of HwCap
    HwCap2 = 26,
    /// Filename of program
    ExecFn = 31,

    SysInfo = 32,
    SysInfoEHdr = 33,
}

pub struct Auxv {
    pub typ: AuxType,
    pub value: u64,
}

impl Auxv {
    // A list of all the auxiliary types we know (and care) about
    const KNOWN_TYPES: &'static [AuxType] = &[
        AuxType::ExecFd,
        AuxType::PHdr,
        AuxType::PhEnt,
        AuxType::PhNum,
        AuxType::PageSz,
        AuxType::Base,
        AuxType::Flags,
        AuxType::Entry,
        AuxType::NotElf,
        AuxType::Uid,
        AuxType::EUid,
        AuxType::Gid,
        AuxType::EGid,
        AuxType::Platform,
        AuxType::HwCap,
        AuxType::ClkTck,
        AuxType::Secure,
        AuxType::BasePlatform,
        AuxType::Random,
        AuxType::HwCap2,
        AuxType::ExecFn,
        AuxType::SysInfo,
        AuxType::SysInfoEHdr,
    ];

    pub fn get(typ: AuxType) -> Option<Self> {
        extern "C" {
            fn getauxval(typ: u64) -> u64;
        }

        unsafe {
            match getauxval(typ as u64) {
                0 => None,
                value => Some(Self { typ, value }),
            }
        }
    }

    pub fn get_known() -> Vec<Self> {
        Self::KNOWN_TYPES
            .iter()
            .copied()
            .filter_map(Self::get)
            .collect()
    }
}