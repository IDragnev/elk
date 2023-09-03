#![feature(asm)]

mod process;
mod name;
mod procfs;
mod auxv;

use thiserror::*;
use std::{
    error::Error,
    fmt,
    ffi::CString,
};
use argh::{
    FromArgs,
};
use auxv::{
    AuxType,
    Auxv,
};

#[derive(FromArgs, PartialEq, Debug)]
/// Top-level command
struct Args {
    #[argh(subcommand)]
    nested: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Autosym(AutosymArgs),
    Run(RunArgs),
    Dig(DigArgs)
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "autosym")]
/// Given a PID, spit out GDB commands to load the symbols of
/// all .so files mapped in memory
struct AutosymArgs {
    #[argh(positional)]
    /// the PID of the proccess to examine
    pid: u32,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "run")]
/// Load and run an ELF executable
struct RunArgs {
    #[argh(positional)]
    /// the absolute path of an executable file to load and run
    exec_path: String,
    #[argh(positional)]
    /// arguments for the executable file
    args: Vec<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "dig")]
/// Shows information about an address in a process' address space
struct DigArgs {
    #[argh(option)]
    /// the PID of the process whose memory space to examine
    pid: u32,
    #[argh(option)]
    /// the address to look for
    addr: u64,
}

fn main() {
    if let Err(e) = do_main() {
        eprintln!("Fatal error: {}", e);
    }
}

fn do_main() -> Result<(), Box<dyn Error>> {
    let args: Args = argh::from_env();
    match args.nested {
        SubCommand::Run(args) => cmd_run(args),
        SubCommand::Autosym(args) => cmd_autosym(args),
        SubCommand::Dig(args) => cmd_dig(args),
    }
}

#[derive(Error, Debug)]
enum ProcessMappingsError {
    #[error("parsing failed: {0}")]
    Parse(String),
}

fn process_mappings<F, T>(pid: u32, f: F) -> Result<T, Box<dyn Error>>
where
    F: Fn(&Vec<procfs::Mapping<'_>>) -> Result<T, Box<dyn Error>>,
{
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid))?;
    match procfs::mappings(&maps) {
        Ok((_, maps)) => f(&maps),
        Err(e) => {
            // parsing errors borrow the input, so we wouldn't be able
            // to return it. to prevent that, format it early.
            Err(Box::new(ProcessMappingsError::Parse(format!("{:?}", e))))
        }
    }
}

fn cmd_autosym(args: AutosymArgs) -> Result<(), Box<dyn Error>> {
    fn analyze(mapping: &procfs::Mapping) -> Result<(), Box<dyn Error>> {
        if mapping.deleted {
            // skip deleted mappings
            return Ok(());
        }

        let path = match mapping.source {
            procfs::Source::File(path) => path,
            _ => return Ok(()),
        };

        let contents = std::fs::read(path)?;
        let file = match delf::File::parse_or_print_error(&contents) {
            Some(x) => x,
            _ => return Ok(()),
        };

        let section = match file
            .section_headers
            .iter()
            .find(|sh| file.shstrtab_entry(sh.name) == b".text")
        {
            Some(section) => section,
            _ => return Ok(()),
        };

        let textaddress = mapping.addr_range.start - mapping.offset + section.file_offset;
        println!("add-symbol-file {:?} 0x{:?}", path, textaddress);

        Ok(())
    }

    process_mappings(args.pid, |mappings| {
        for mapping in mappings.iter().filter(|m| m.perms.x && m.source.is_file()) {
            analyze(mapping)?;
        }
        Ok(())
    })
}

struct Size(pub delf::Addr);

impl fmt::Debug for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const KIB: u64 = 1024;
        const MIB: u64 = 1024 * KIB;

        let x = (self.0).0;
        #[allow(overlapping_range_endpoints)]
        #[allow(clippy::clippy::match_overlapping_arm)]
        match x {
            0..=KIB => write!(f, "{} B", x),
            KIB..=MIB => write!(f, "{} KiB", x / KIB),
            _ => write!(f, "{} MiB", x / MIB),
        }
    }
}

fn cmd_dig(args: DigArgs) -> Result<(), Box<dyn Error>> {
    let addr = delf::Addr(args.addr);

    process_mappings(args.pid, |mappings| {
        let mapping = match mappings.iter().find(|m| m.addr_range.contains(&addr)) {
            Some(m) => m,
            None => {
                println!("Could not find {:?}", addr);
                return Ok(())
            },
        };

        println!("Mapped {:?} from {:?}", mapping.perms, mapping.source);
        println!(
            "(Map range: {:?}, {:?} total)",
            mapping.addr_range,
            Size(mapping.addr_range.end - mapping.addr_range.start),
        );

        let path = match mapping.source {
            procfs::Source::File(p) => p,
            _ => return Ok(()),
        };

        let contents = std::fs::read(path)?;
        let file = match delf::File::parse_or_print_error(&contents) {
            Some(x) => x,
            _ => return Ok(())
        };

        let offset = addr + mapping.offset - mapping.addr_range.start;
        let segment = match file
            .program_headers
            .iter()
            .find(|ph| ph.file_range().contains(&offset))
        {
            Some(s) => s,
            None => return Ok(()),
        };

        let vaddr = offset + segment.vaddr - segment.offset;
        println!("Object virtual address: {:?}", vaddr);

        let section = match file
            .section_headers
            .iter()
            .find(|sh| sh.mem_range().contains(&vaddr))
        {
            Some(s) => s,
            None => return Ok(()),
        };

        let section_name = file.shstrtab_entry(section.name);
        let section_offset = vaddr - section.addr;
        println!(
            "At section {:?} + {} (0x{:x})",
            String::from_utf8_lossy(section_name),
            section_offset.0,
            section_offset.0,
        );

        match file.read_symtab_entries() {
            Ok(syms) => {
                for sym in &syms {
                    let sym_range = sym.value..(sym.value + delf::Addr(sym.size));
                    if sym.value == vaddr || sym_range.contains(&vaddr) {
                        let sym_offset = vaddr - sym.value;
                        let sym_name = String::from_utf8_lossy(file.strtab_entry(sym.name));
                        println!(
                            "At symbol {:?} + {} (0x{:x})",
                            sym_name,
                            sym_offset.0,
                            sym_offset.0,
                        );
                    }
                }
            },
            Err(e) => println!("Could not read syms: {:?}", e),
        }

        Ok(())
    })
}

fn cmd_run(args: RunArgs) -> Result<(), Box<dyn Error>> {
    let mut proc = process::Process::new();
    let exec_index = proc.load_object_and_dependencies(args.exec_path.clone())?;
    proc.apply_relocations()?;
    proc.adjust_protections()?;

    let exec = &proc.objects[exec_index];
    let args = std::iter::once(CString::new(args.exec_path.as_bytes()).unwrap())
        .chain(
            args.args.iter().map(|s| CString::new(s.as_bytes()).unwrap()),
        )
        .collect();

    let opts = StartOptions {
        exec,
        args,
        env: std::env::vars()
            .map(|(k, v)| CString::new(format!("{}={}", k, v)).unwrap())
            .collect(),
        auxv: Auxv::get_known(), // temporary
    };
    start(&opts);

    Ok(())
}

pub struct StartOptions<'a> {
    pub exec: &'a process::Object,
    pub args: Vec<CString>,
    pub env: Vec<CString>,
    pub auxv: Vec<Auxv>,
}

pub fn start(opts: &StartOptions) {
    let exec = opts.exec;
    let entry_point = exec.file.entry_point + exec.base;
    let stack = build_stack(opts);

    unsafe {
        jmp(entry_point.as_ptr(), stack.as_ptr(), stack.len());
    }
}

fn build_stack(opts: &StartOptions) -> Vec<u64> {
    let mut stack: Vec<u64> = Vec::new();

    let null = 0_u64;

    macro_rules! push {
        ($x:expr) => {
            stack.push($x as u64)
        };
    }

    // argc
    push!(opts.args.len());

    // argv
    for v in &opts.args {
        push!(v.as_ptr());
    }
    push!(null);

    // envp
    for v in &opts.env {
        push!(v.as_ptr());
    }
    push!(null);

    // auxv
    for v in &opts.auxv {
        push!(v.typ);
        push!(v.value);
    }
    push!(AuxType::Null);
    push!(null);

    // align stack to 16-byte boundary
    if stack.len() % 2 == 1 {
        stack.push(0);
    }

    stack
}

#[inline(never)]
unsafe fn jmp(entry_point: *const u8, stack_contents: *const u64, qword_count: usize) {
    use core::arch::asm;

    asm!(
        // allocate (qword_count * 8) bytes
        "mov {tmp}, {qword_count}",
        "sal {tmp}, 3",
        "sub rsp, {tmp}",

        "2:",
        // start at i = (n-1)
        "sub {qword_count}, 1",
        // copy qwords to the stack
        "mov {tmp}, QWORD PTR [{stack_contents}+{qword_count}*8]",
        "mov QWORD PTR [rsp+{qword_count}*8], {tmp}",
        // loop if i isn't zero, break otherwise
        "test {qword_count}, {qword_count}",
        "jnz 2b",

        "jmp {entry_point}",

        entry_point = in(reg) entry_point,
        stack_contents = in(reg) stack_contents,
        qword_count = in(reg) qword_count,
        tmp = out(reg) _,
    )
}