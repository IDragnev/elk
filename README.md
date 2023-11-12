# elk
[ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) executable &amp; linker kit. A minimal ELF dynamic loader with its own ELF parser and two useful commands to be used in GDB sessions. Written for fun and learning purpose while reading [this series](https://fasterthanli.me/series/making-our-own-executable-packer).  
The dynamic loader can be used only on single-threaded executables. It is built bottom-up by inspecting many different executables while learning more about ELF, so don't be surprised if it fails to load some executable.

## Usage
`elk <command> [<args>]`

Options:  
  `--help` - display usage information  

Commands:  
 - `run <path>`  
 Load and run an ELF executable
 - `autosym <pid>`  
 Given a PID, spit out GDB commands to load the symbols of all .so files mapped in memory
 - `dig <address>`  
 Shows information about an address in a process' address space

In order to use `autosym` and `dig`, you should install elk and use them in GDB sessions. Example usage:  
```
#in elk
cargo install --path ./elk      
gdb <path_to_exec>    
(gdb) starti  
(gdb) autosym  
...    
(gdb) dig 0xbeefface
```  
