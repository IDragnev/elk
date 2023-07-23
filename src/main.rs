mod process;
mod name;

use std::{
    env,
    error::Error,
};
use argh::{
    FromArgs,
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
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "autosym")]
/// Given a PID, spit out GDB commands to load all .so files
/// mapped in memory
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
    }
}

fn cmd_autosym(args: AutosymArgs) -> Result<(), Box<dyn Error>> {
    todo!()
}

fn cmd_run(args: RunArgs) -> Result<(), Box<dyn Error>> {
    let mut proc = process::Process::new();
    let exec_index = proc.load_object_and_dependencies(args.exec_path)?;
    proc.apply_relocations()?;
    proc.adjust_protections()?;

    let exec_obj = &proc.objects[exec_index];
    let entry_point = exec_obj.file.entry_point + exec_obj.base;
    unsafe { jmp(entry_point.as_ptr()) };

    Ok(())
}

unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}