extern crate libc;

use libc::*;
use std::ffi::{CString, CStr};
use std::io::{Read, Write};
use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::ptr;


// Определите необходимые типы и константы
pub type thread_act_t = mach_port_t;
pub type thread_state_t = *mut i32; // or *mut u32 or what's appropriate for your case


type mach_port_name_t = u32;

type thread_state_flavor_t = i32;


#[repr(C)]
struct arm_thread_state64_t {
    x: [u64; 31],
    fp: u64,
    lr: u64,
    sp: u64,
    pc: u64,
    cpsr: u32,
}

pub const ARM_THREAD_STATE64: u32 = 6;


// Количество элементов в thread_state_t для arm_unified_thread_state
const ARM_UNIFIED_THREAD_STATE_COUNT: mach_msg_type_number_t =
    (std::mem::size_of::<arm_thread_state64_t>() / std::mem::size_of::<u32>()) as mach_msg_type_number_t;


// Определите FFI функции
extern "C" {
    pub fn thread_get_state(
        target_act: thread_act_t,
        flavor: u32,
        thread_state: thread_state_t,
        thread_state_count: mach_msg_type_number_t,
    ) -> kern_return_t;

    pub fn thread_set_state(
        target_act: thread_act_t,
        flavor: u32,
        thread_state: thread_state_t,
        thread_state_count: mach_msg_type_number_t,
    ) -> kern_return_t;
}



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

                let mut status: c_int = 0;
                ptrace(PT_ATTACH, pid, ptr::null_mut(), 0);
                waitpid(pid, &mut status, 0);

                // Для получения потока дочернего процесса вам, возможно, понадобится другой метод,
                // но для простоты используем mach_thread_self() (это не правильно!)
                let thread = mach_thread_self();

                // Получаем состояние регистров потока
                // let mut state: arm_thread_state64_t = std::mem::zeroed();
                // let mut state_count: mach_msg_type_number_t = ARM_UNIFIED_THREAD_STATE_COUNT;
                // thread_get_state(thread, ARM_THREAD_STATE64, &mut state as *mut _ as thread_state_t, state_count);

                let mut state: arm_thread_state64_t = unsafe { std::mem::zeroed() };
                let mut state_count: mach_msg_type_number_t = ARM_UNIFIED_THREAD_STATE_COUNT;
                unsafe {
                    thread_get_state(thread, ARM_THREAD_STATE64, &mut state as *mut _ as thread_state_t, state_count);
                }

                // Изменяем состояние регистра или делаем другие действия

                // Устанавливаем измененное состояние регистров обратно в поток
                thread_set_state(thread, ARM_THREAD_STATE64, &mut state as *mut _ as thread_state_t, state_count);

                // Продолжаем выполнение дочернего процесса
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
