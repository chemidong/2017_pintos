#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
/* for filesys use */
#include "filesys/filesys.h"
#include "filesys/file.h"
/* for accessing user memory */
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

/* syscall regarding files */
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);

/* syscall regarding pid */
int exec (const char * cmd_line);
int wait (int pid);

/* lock for accessing file - for synchronization purpose */
struct lock file_lock;



void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  //printf ("system call!\n");

  int args[3];     /* For arguments - maximum three for syscalls */

  /* FIRST switch-case for confirming arguments */
  switch (*(int*)f->esp)
  {
    /* one-argument syscalls */
    case SYS_EXIT:
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_TELL:
    case SYS_CLOSE:
      if(!is_user_vaddr(f->esp + 4)){ exit(-1); }
      args[0] = *(int *)(4 + f->esp);
      break;
    /* two-argument syscalls */
    case SYS_CREATE:
    case SYS_SEEK:
      if(!is_user_vaddr(f->esp + 4) || !is_user_vaddr(f->esp + 8)){ exit(-1); }
      args[0] = *(int *)(4 + f->esp);
      args[1] = *(int *)(8 + f->esp);
      break;
    /* three-argument syscalls */
    case SYS_READ:
    case SYS_WRITE:
      if(!is_user_vaddr(f->esp + 4) || !is_user_vaddr(f->esp + 8) || !is_user_vaddr (f->esp + 12)){ exit(-1); }
      args[0] = *(int *)(4 + f->esp);
      args[1] = *(int *)(8 + f->esp);
      args[2] = *(int *)(12 + f->esp);
      break;
  }

  /* SECOND switch-case for calling each syscalls */
  switch (*(int*)f->esp)
  {
    /* SYSCALL for working minimally */
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      exit(args[0]);
      break;
    case SYS_WRITE:
      f->eax = write(args[0], (const void*)args[1], (unsigned int)args[2]);
      break;

    /* SYSCALL regarding files */
    case SYS_CREATE:
      if (args[0] == NULL){ exit(-1); }
      else{
        f->eax = create((const char*)args[0], (unsigned)args[1]);
      }
      break;
    case SYS_REMOVE:
      f->eax = remove((const char*)args[0]);
      break;
    case SYS_OPEN:
      if (args[0] == NULL){ exit(-1); }
      else{
        f->eax = open((const char*)args[0]);
      }
      break;
    case SYS_FILESIZE:
      f->eax = filesize((int)args[0]);
      break;
    case SYS_READ:
      f->eax = read((int)args[0],(const void *)args[1],(unsigned)args[2]);
      break;
    case SYS_SEEK:
      seek((int)args[0], (unsigned)args[1]);
      break;
    case SYS_TELL:
      f->eax = tell((int)args[0]);
      break;
    case SYS_CLOSE:
      close((int)args[0]);
      break;
    /* SYSCALL regarding pid */
    case SYS_EXEC:
      f->eax = exec((const char *)args[0]);
      break;
    case SYS_WAIT:
     f->eax = wait((int)args[0]);
      break;
  }
}

/* struct thread_file for thread to hold a list of files */
struct thread_file
{
  struct file * file;
  int fd;
  struct list_elem file_elem;
};
/* END of struct declaration */

struct thread_file * search_fd(int fd)
{
  struct list *file_list  = &thread_current ()->file_list;
  struct list_elem * itr;
  for(itr = list_begin(file_list);itr != list_end(file_list);itr=list_next(itr))
  {
    struct thread_file *ifile = list_entry(itr, struct thread_file, file_elem);
    if(ifile->fd == fd)
      return ifile;
  }
  return NULL;
}
/* syscall functions */
void
halt (void)
{
  power_off();
}

void
exit (int status)
{
  struct thread * curr = thread_current();
  curr->exit_status = status;
  struct list_elem* itr;

  while(!list_empty(&curr->file_list))
  {
    itr = list_pop_front(&curr->file_list);
    close(list_entry(itr, struct thread_file, file_elem)->fd);
  }

  thread_exit ();
}

int
exec (const char *cmd_line)
{
  if(cmd_line != NULL && is_user_vaddr(cmd_line) && pagedir_get_page(thread_current ()->pagedir, cmd_line) != NULL)
    return process_execute(cmd_line);
}

int
wait (int pid)
{
  return process_wait(pid);
}

bool
create (const char *file, unsigned initial_size)
{
  if(file == NULL || !is_user_vaddr(file) || pagedir_get_page (thread_current ()->pagedir, file) == NULL){
    exit(-1); 
  }
  lock_acquire(&file_lock);
  bool success = filesys_create (file, (off_t)initial_size);
  lock_release(&file_lock);
  return success;
}

bool
remove (const char *file)
{
  if(!is_user_vaddr(file) || file == NULL || pagedir_get_page(thread_current ()->pagedir, file) == NULL){ return -1; }
  lock_acquire(&file_lock);
  bool success = filesys_remove (file);
  lock_release(&file_lock);
  return success;
}

int 
open (const char *file)
{
  struct file* openfile;
  lock_acquire(&file_lock);
  openfile = filesys_open(file);
  if (openfile == NULL)
  {
    lock_release(&file_lock);
    return -1;
  }
  else
  {
    int fd = thread_current()->fd_grant;
    thread_current()->fd_grant = fd + 1;

    /* need to add list of thread file struct to thread.h and add thread file struct with file, fd, elem */
    struct thread_file *thread_file;
    thread_file = malloc(sizeof(struct thread_file));
    thread_file->file = openfile;
    thread_file->fd = fd;
    list_push_back(&thread_current()->file_list, &thread_file->file_elem);
    lock_release(&file_lock);
    return fd;
  }
}

int
filesize (int fd)
{
  struct thread_file * itrfile=search_fd(fd);
  if(itrfile != NULL)
  {
      lock_acquire(&file_lock);
      int fl = file_length(itrfile->file);
      lock_release(&file_lock);
      return fl;
  }
  else
    return -1;
}

int
read (int fd, void *buffer, unsigned size)
{
  if (!is_user_vaddr(buffer)||!is_user_vaddr(buffer+size)){
    exit(-1); 
  }
  if (fd == 0)
  {
    /* std in*/
    int itr;
    for (itr = 0; itr < size; itr++)
    {
      *(uint8_t*)(buffer+itr) = input_getc ();
    }
    return size;
  }
  else if (fd == 1){ return -1; }
  else
  {
    struct thread_file * itrfile = search_fd(fd);
    int fr;
    if(itrfile != NULL)
    {
      lock_acquire(&file_lock);
      fr = file_read (itrfile->file, buffer, size);
      lock_release(&file_lock);
      return fr;
    }
    return -1;
  }
}

int
write (int fd, const void * buffer, unsigned int size)
{
  int written=-1;
  if (!is_user_vaddr(buffer)||!is_user_vaddr(buffer+size)||buffer == NULL || pagedir_get_page(thread_current ()->pagedir, buffer) == NULL || pagedir_get_page(thread_current ()->pagedir, buffer+size) == NULL)
  {
    exit(-1);
  }
  if (fd == 1){ 
    putbuf(buffer, size);
    return size;
  }
  else if (fd == 0){ return -1; }
  else
  {
    struct thread_file * itrfile = search_fd(fd);
    int fw;
    if(itrfile != NULL) 
    {
      lock_acquire(&file_lock);
      fw = file_write(itrfile->file, buffer, size);
      lock_release(&file_lock);
      return fw;
    }
    return -1;
  }
}

void
seek (int fd, unsigned position)
{
  if (fd == 0 || fd == 1){ return ; }
  struct thread_file * itrfile = search_fd(fd);
  if(itrfile != NULL)
    file_seek(itrfile->file, position);
}

unsigned
tell (int fd)
{
  if (fd == 0 || fd == 1 ){ return -1; }
  struct thread_file* itrfile=search_fd(fd);
  if(itrfile != NULL)
    return (unsigned)file_tell(itrfile->file);
  else
    return -1;
}

void
close (int fd)
{
  if (fd == 0 || fd == 1){ return; }
  struct thread_file* itrfile = search_fd(fd);
  if(itrfile != NULL)
  {
    file_close(itrfile->file);
    list_remove(&itrfile->file_elem);
    free(itrfile);
  }
}

