extern crate libc;

use libc::*;
use std::ffi::CString;
use std::io::{Read, Write};
use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::ptr;

fn main() {
    let mut pipe_fd: [c_int; 2] = [0, 0];

    if unsafe { pipe(pipe_fd.as_mut_ptr()) } != 0 {
        panic!("Failed to create pipe");
    }

    let pid = unsafe { fork() };

    match pid {
        -1 => panic!("Failed to fork"),
        0 => {
            // Child process
            unsafe {
                close(pipe_fd[0]);  // Close the read end of the pipe in child process

                dup2(pipe_fd[1], STDOUT_FILENO);  // Redirect child's stdout to the pipe
                close(pipe_fd[1]);

                let cmd = CString::new("ls").unwrap();
                let arg = CString::new("/").unwrap();
                let args = [
                    cmd.as_ptr(),
                    arg.as_ptr(),
                    ptr::null()
                ];
                execvp(cmd.as_ptr(), args.as_ptr());
            }
        }
        _ => {
            // Parent process (tracer)
            unsafe {
                close(pipe_fd[1]);  // Close the write end of the pipe in parent process

                // Attach to the child process
                ptrace(PT_ATTACH, pid, ptr::null_mut(), 0);
                let mut status: c_int = 0;
                waitpid(pid, &mut status, 0);

                // Continue child process
                ptrace(PT_CONTINUE, pid, ptr::null_mut(), 0);
            }

            // Read from the pipe to capture child's output
            let mut output_file = unsafe { File::from_raw_fd(pipe_fd[0]) };
            let mut output = String::new();
            output_file.read_to_string(&mut output).unwrap();
            println!("{}", output);
        }
    }
}
