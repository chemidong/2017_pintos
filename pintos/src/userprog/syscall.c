#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "thread/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
struct thread_file
{
  struct file *f;
  int fd;
  struct list_elem file_elem;
};
void halt()
{
  power_off();
}
void exit(int status)
{
  thread_current()->exit_status = status; 
  return;
}
pid_t exec(const char *cmd_line)
{
  if(validate(cmd_line))
    return (pid_t)process_execute(cmd_line);
}
int wait(pid_t pid)
{
  return process_wait(pid);
}
bool create(const char *file, unsigned initial_size)
{
  if(validate(file))
    return filesys_create(file, initial_size);
}
bool remove(const char *file)
{
  if(validate(file))
    return filesys_remove(file);
}
int open(const char *file)
{
  if(validate(file))
  {
    struct file *f = filesys_open(file);
    if(f==NULL) 
      return -1;
    struct thread_file * tf = (struct thread_file *) malloc(sizeof struct thread_file *);
    tf->f = f;
     
    thread_current()->files 
  }
  return -1;
}
int filesize(int fd)
{
  return -1;
}
int read(int fd, void *buffer, unsigned size)
{
  return -1;
}
int write (int fd, const void *buffer, unsigned size)
{
  if(validate(buffer)&&validate(buffer+size))
  {
    if(fd == 1)
    {
      putbuf((char *)buffer, size);
      return size;
    }
    else if(fd == 0)
      return -1;
    else
    {

    }
  }
  return -1; 
}
void seek (int fd, unsigned position)
{
  return;
}
unsigned tell (int fd)
{
  return 0;
}
void close (int fd)
{
}
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
bool validate(void *p)
{
  if(p >= PHYS_BASE || p == NULL ||pagedir_get_page(thread_current()->pagedir, arg)==NULL )
  {
    thread_current()->exit_status  = -1;
    thread_exit();
  }
  return true;
}
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  if(validate(f->esp))
  {
    int intr_n =*((int *)f->esp);
    // intr_n shuld be loaded
    switch(intr_n)
    {
      case SYS_HALT:
        halt();
        break;
      case SYS_EXIT:
        exit(*((int *)f->esp + 4));
        f->eax = *((int *)f->esp + 4);
        thread_exit();
      case SYS_EXEC:
        f->eax = exec(*((char **)f->esp + 4));
        break;
      case SYS_WAIT:
        f->eax = wait(*((int *)f->esp + 4));
        thread_exit();
        break;
      case SYS_CREATE:
        f->eax = create(*((char **)f->esp + 4),*((int *)f->esp + 8));
        break;
      case SYS_REMOVE:
        f->eax = remove(*((char **)f->esp + 4));
        break;
      case SYS_OPEN:
        f->eax = open(*((char **)f->esp + 4));
        break;
      case SYS_FILESIZE:
        f->eax = filesize(*((int *)f->esp + 4));
        break;
      case SYS_READ:
        f->eax = read(*((int *)f->esp + 4),*((void **)f->esp + 8),*((int *)f->esp + 12));
        break;
      case SYS_WRITE:
        f->eax = write(*((int *)f->esp + 4),*((void **)f->esp + 8),*((int *)f->esp + 12));
        break;
      case SYS_SEEK:
        seek(*((int *)f->esp + 4),*((int *)f->esp + 8));
        break;
      case SYS_TELL:
        f->eax = tell (*((int *)f->esp + 4));
        break;
      case SYS_CLOSE:
        close (*((int *)f->esp + 4));
        break;
      default:
        thread_exit();
    }
  }
}
