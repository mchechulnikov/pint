#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <mach/mach.h>


bool is_printable_string(const char* str) {
    for (const char* p = str; *p; p++) {
        if (!isprint((unsigned char)*p)) {
            return false;
        }
    }
    return true;
}

bool read_registers(pid_t pid, vm_address_t* x0, vm_address_t* x1, vm_address_t* x2, vm_address_t* x8) {
    thread_act_array_t thread_list;
    mach_msg_type_number_t thread_count;
    task_t task;

    // Получаем задачу (task) для дочернего процесса
    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) {
        printf("Failed to get task for pid");
        return false;
    }

    // Получаем список всех потоков для задачи
    if (task_threads(task, &thread_list, &thread_count) != KERN_SUCCESS) {
        printf("Failed to get thread list for task");
        return false;
    }

    // Так как execve был вызван в основном потоке, будем читать регистры основного потока
    // (хотя в реальных условиях вам, возможно, потребуется определить, какой поток вызвал execve)
    thread_t main_thread = thread_list[0];

    arm_thread_state64_t state;
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;

    // Получаем состояние регистров основного потока
    if (thread_get_state(main_thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count) != KERN_SUCCESS) {
        printf("Failed to get thread state");
        return false;
    }

    // Устанавливаем значения регистров
    *x0 = state.__x[0];
    *x1 = state.__x[1];
    *x2 = state.__x[2];
    *x8 = state.__x[8];

    // Освобождаем список потоков
    for (unsigned i = 0; i < thread_count; i++) {
        mach_port_deallocate(mach_task_self(), thread_list[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)thread_list, sizeof(thread_t) * thread_count);

    return true;
}


char* read_memory_string(task_t child_task, vm_address_t address) {
    vm_size_t out_size;
    char buffer[1000000]; // Допустим, что 512 байт - это максимальная длина строки
    kern_return_t result = vm_read_overwrite(child_task, address, sizeof(buffer), (vm_address_t)buffer, &out_size);
    if (result != KERN_SUCCESS) {
        fprintf(stderr, "vm_read_overwrite failed: %s\n", mach_error_string(result));
        return NULL;
    }

    return strdup(buffer);
}



int main() {
    pid_t pid;
    int status;

    pid = fork();

    if (pid < 0) {
        perror("fork failed");
        exit(1);
    }

    if (pid == 0) {
        ptrace(PT_TRACE_ME, 0, NULL, 0);
//        raise(SIGSTOP);
        char *argv[] = {"-l", NULL};
        char *envp[] = {NULL};
        execve("/bin/ls", argv, envp);
        perror("execve failed");
        exit(1);
    } else {

                ptrace(PT_ATTACHEXC, pid, (char*) NULL, 0);
//            waitpid(pid, &status, 0);
//            if (WIFSTOPPED(status)) {

        while (1) {
                printf("Child has stopped. Inspecting arguments...\n");

                task_t child_task;
                if (task_for_pid(mach_task_self(), pid, &child_task) != KERN_SUCCESS) {
                    fprintf(stderr, "Failed to get task for pid %d\n", pid);
                    exit(1);
                }

            exception_mask_t       saved_masks[EXC_TYPES_COUNT];
            mach_port_t            saved_ports[EXC_TYPES_COUNT];
            exception_behavior_t   saved_behaviors[EXC_TYPES_COUNT];
            thread_state_flavor_t  saved_flavors[EXC_TYPES_COUNT];
            mach_msg_type_number_t saved_exception_types_count;

            task_get_exception_ports(child_task,
                                     EXC_MASK_ALL,
                                     saved_masks,
                                     &saved_exception_types_count,
                                     saved_ports,
                                     saved_behaviors
            saved_flavors);

/* allocate and authorize a new port */

            mach_port_allocate(mach_task_self(),
                               MACH_PORT_RIGHT_RECEIVE,
                               &target_exception_port);

            mach_port_insert_right(mach_task_self(),
                                   target_exception_port,
/* and again */        target_exception_port,
                                   MACH_MSG_TYPE_MAKE_SEND);

/* register the exception port with the target process */

            task_set_exception_ports(target_task_port,
                                     EXC_MASK_ALL,
                                     target_exception_port,
                                     EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
                                     THREAD_STATE_NONE);



                char req[128], rpl[128];            /* request and reply buffers */

                mach_msg((mach_msg_header_t *)req,  /* receive buffer */
                     MACH_RCV_MSG,              /* receive message */
                     0,                         /* size of send buffer */
                     sizeof(req),               /* size of receive buffer */
                     target_exception_port,     /* port to receive on */
                     MACH_MSG_TIMEOUT_NONE,     /* wait indefinitely */
                     MACH_PORT_NULL);           /* notify port, unused */

                /* suspend all threads in the process after an exception was received */

                    task_suspend(child_task);


                vm_address_t x0_val; // filename
                vm_address_t x1_val; // argv[]
                vm_address_t x2_val; // envp[]
                vm_address_t x8_val;
                if (!read_registers(pid, &x0_val, &x1_val, &x2_val, &x8_val)) {
                    fprintf(stderr, "Failed to read registers\n");
                    exit(1);
                } else {
                    printf("x0: %lu\nx1: %lu\nx2: %lu\nx8: %lu\n", x0_val, x1_val, x2_val, x8_val);
                }

                // check sys call
                if (x8_val != SYS___mac_execve && x8_val != SYS_execve) {
                    fprintf(stderr, "Not an execve syscall\n");
                    continue;
                }


                char *filename = read_memory_string(child_task, x0_val);
                printf("Filename: %s\n", filename);
                free(filename);

                ptrace(PT_CONTINUE, pid, (caddr_t) 1, 0);
                break;

//            char **argv = read_memory_string_array(child_task, x1_val);
//            for (int i = 0; argv[i]; ++i) {
//                printf("Arg[%d]: %s\n", i, argv[i]);
//                free(argv[i]);
//            }
//            free(argv);
//
//            char **envp = read_memory_string_array(child_task, x2_val);
//            for (int i = 0; envp[i]; ++i) {
//                printf("Env[%d]: %s\n", i, envp[i]);
//                free(envp[i]);
//            }
//            free(envp);

        }
    }

    return 0;
}



//#include <stdio.h>
//#include <stdlib.h>
//#include <signal.h>
//#include <ctype.h>
//#include <unistd.h>
//#include <sys/ptrace.h>
//#include <sys/types.h>
//#include <sys/wait.h>
//#include <mach/mach.h>
//
//bool is_printable_string(const char* str) {
//    for (const char* p = str; *p; p++) {
//        if (!isprint((unsigned char)*p)) {
//            return false;
//        }
//    }
//    return true;
//}
//
//
//int main() {
//    pid_t pid;
//    int status;
//
//    pid = fork();
//
//    if (pid < 0) {
//        perror("fork failed");
//        exit(1);
//    }
//
//    if (pid == 0) {
//        sleep(1);
//        ptrace(PT_TRACE_ME, 0, NULL, 0);
//        raise(SIGSTOP);
//        execlp("/bin/ls", "ls", "-l", (char*)NULL);
////        perror("execlp failed");
////        exit(1);
//    } else {
//        waitpid(pid, &status, 0);
//        if (WIFSTOPPED(status)) {
//            printf("Child has stopped. Inspecting arguments...\n");
//
//            task_t child_task;
//            if (task_for_pid(mach_task_self(), pid, &child_task) != KERN_SUCCESS) {
//                fprintf(stderr, "Failed to get task for pid %d\n", pid);
//                exit(1);
//            }
//
//            vm_address_t address = VM_MIN_ADDRESS;
//            vm_size_t size = 0;
//            vm_region_basic_info_data_64_t info;
//            mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
//            mach_port_t object_name;
//
//            while (1) {
//                if (vm_region_64(child_task, &address, &size, VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &info_count, &object_name) != KERN_SUCCESS) {
//                    break;
//                }
//
//                char *buffer = malloc(size);
//                mach_msg_type_number_t data_count = size;
//
//                vm_size_t out_size = size;
//
//                if (vm_read_overwrite(child_task, address, size, (vm_address_t)buffer, &out_size) == KERN_SUCCESS) {
//                    char *current_str = buffer;
//                    for (int i = 0; i < size; i++) {
//                        if (buffer[i] == '\0') { // Конец строки
//                            if (current_str < buffer + i) { // Если есть текст между текущим и предыдущим нулевым байтом
//                                if (is_printable_string(current_str)) {
//                                    printf("Found string: %s\n", current_str);
//                                }
//                            }
//                            current_str = buffer + i + 1; // Начало следующей строки
//                        }
//                    }
//                }
//
//                free(buffer);
//                address += size;
//            }
//
//            ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
//        }
//    }
//
//    return 0;
//}
//
//
