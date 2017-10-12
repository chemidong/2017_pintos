#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include <debug.h>
typedef int pid_t;

void syscall_init (void) NO_RETURN;
#endif /* userprog/syscall.h */
