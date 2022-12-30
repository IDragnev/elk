mod process;

use std::{
    env,
    error::Error,
};

fn main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("usage: elk FILE");

    let mut proc = process::Process::new();
    let exec_index = proc.load_object_and_dependencies(input_path)?;
    proc.apply_relocations()?;
    proc.adjust_protections()?;
    // println!("{:#?}", proc);

    let exec_obj = &proc.objects[exec_index];
    let entry_point = exec_obj.file.entry_point + exec_obj.base;
    unsafe { jmp(entry_point.as_ptr()) };

    Ok(())
}

unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}