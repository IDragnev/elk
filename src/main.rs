mod process;

use std::{
    env,
    error::Error,
};

fn main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("usage: elk FILE");

    let mut proc = process::Process::new();
    proc.load_object_and_dependencies(input_path)?;
    println!("{:#?}", proc);

    Ok(())
}