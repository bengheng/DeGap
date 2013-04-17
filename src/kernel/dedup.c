/* dedup.c
 *
 * Removes duplicated auditd events. The "dd_" prefix indicates dedup functions.
 * */

#ifdef __KERNEL__
#include <linux/init.h>
#include <asm/types.h>
#include <asm/atomic.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/socket.h>
#include <linux/mqueue.h>
#include <linux/audit.h>
#include <linux/personality.h>
#include <linux/time.h>
#include <linux/netlink.h>
#include <linux/compiler.h>
#include <asm/unistd.h>
#include <linux/security.h>
#include <linux/list.h>
#include <linux/tty.h>
#include <linux/binfmts.h>
#include <linux/highmem.h>
#include <linux/syscalls.h>
#include <linux/inotify.h>
#include <linux/capability.h>
#include <linux/fs_struct.h>
#include <linux/kernel.h> // for printk
#include <linux/limits.h> // for PATH_MAX
#include "audit.h"
#include "sha2.h"
#else
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>
#include "dedup_event.h"
#endif

#include "dedup_shatree.h"

#ifdef __KERNEL__

//=============================================================================
// Stuff from auditsc.c
// We don't want to put them in a shared header file because we don't want to
// mess things up, and are trying to keep Dedup as self-contained as possible.

/* AUDIT_NAMES is the number of slots we reserve in the audit_context
 * for saving names from getname(). */
#define AUDIT_NAMES    20

/* Indicates that audit should log the full pathname. */
#define AUDIT_NAME_FULL -1

/* no execve audit message should be longer than this (userspace limits) */
#define MAX_EXECVE_AUDIT_LEN 7500

struct audit_cap_data {
  kernel_cap_t		permitted;
  kernel_cap_t		inheritable;
  union {
    unsigned int	fE;		/* effective bit of a file capability */
    kernel_cap_t	effective;	/* effective set of a process */
  };
};

/* When fs/namei.c:getname() is called, we store the pointer in name and
 * we don't let putname() free it (instead we free all of the saved
 * pointers at syscall exit time).
 *
 * Further, in fs/namei.c:path_lookup() we store the inode and device. */
struct audit_names {
  const char	*name;
  int		name_len;	/* number of name's characters to log */
  unsigned	name_put;	/* call __putname() for this name */
  unsigned long	ino;
  dev_t		dev;
  umode_t		mode;
  uid_t		uid;
  gid_t		gid;
  dev_t		rdev;
  u32		osid;
  struct audit_cap_data fcap;
  unsigned int	fcap_ver;
};

struct audit_aux_data {
  struct audit_aux_data	*next;
  int			type;
};

#define AUDIT_AUX_IPCPERM	0

/* Number of target pids per aux struct. */
#define AUDIT_AUX_PIDS	16

struct audit_aux_data_execve {
  struct audit_aux_data	d;
  int argc;
  int envc;
  struct mm_struct *mm;
};

struct audit_aux_data_pids {
  struct audit_aux_data	d;
  pid_t			target_pid[AUDIT_AUX_PIDS];
  uid_t			target_auid[AUDIT_AUX_PIDS];
  uid_t			target_uid[AUDIT_AUX_PIDS];
  unsigned int		target_sessionid[AUDIT_AUX_PIDS];
  u32			target_sid[AUDIT_AUX_PIDS];
  char 			target_comm[AUDIT_AUX_PIDS][TASK_COMM_LEN];
  int			pid_count;
};

struct audit_aux_data_bprm_fcaps {
  struct audit_aux_data	d;
  struct audit_cap_data	fcap;
  unsigned int		fcap_ver;
  struct audit_cap_data	old_pcap;
  struct audit_cap_data	new_pcap;
};

struct audit_aux_data_capset {
  struct audit_aux_data	d;
  pid_t			pid;
  struct audit_cap_data	cap;
};

struct audit_tree_refs {
  struct audit_tree_refs *next;
  struct audit_chunk *c[31];
};

/* The per-task audit context. */
struct audit_context {
  int		    dummy;	/* must be the first element */
  int		    in_syscall;	/* 1 if task is in a syscall */
  enum audit_state    state, current_state;
  unsigned int	    serial;     /* serial number for record */
  int		    major;      /* syscall number */
  struct timespec	    ctime;      /* time of syscall entry */
  unsigned long	    argv[4];    /* syscall arguments */
  long		    return_code;/* syscall return code */
  u64		    prio;
  int		    return_valid; /* return code is valid */
  int		    name_count;
  struct audit_names  names[AUDIT_NAMES];
  char *		    filterkey;	/* key for rule that triggered record */
  struct path	    pwd;
  struct audit_context *previous; /* For nested syscalls */
  struct audit_aux_data *aux;
  struct audit_aux_data *aux_pids;
  struct sockaddr_storage *sockaddr;
  size_t sockaddr_len;
  /* Save things to print about task_struct */
  pid_t		    pid, ppid;
  uid_t		    uid, euid, suid, fsuid;
  gid_t		    gid, egid, sgid, fsgid;
  unsigned long	    personality;
  int		    arch;

  pid_t		    target_pid;
  uid_t		    target_auid;
  uid_t		    target_uid;
  unsigned int	    target_sessionid;
  u32		    target_sid;
  char		    target_comm[TASK_COMM_LEN];

  struct audit_tree_refs *trees, *first_trees;
  struct list_head killed_trees;
  int tree_count;

  int type;
  union {
    struct {
      int nargs;
      long args[6];
    } socketcall;
    struct {
      uid_t			uid;
      gid_t			gid;
      mode_t			mode;
      u32			osid;
      int			has_perm;
      uid_t			perm_uid;
      gid_t			perm_gid;
      mode_t			perm_mode;
      unsigned long		qbytes;
    } ipc;
    struct {
      mqd_t			mqdes;
      struct mq_attr 		mqstat;
    } mq_getsetattr;
    struct {
      mqd_t			mqdes;
      int			sigev_signo;
    } mq_notify;
    struct {
      mqd_t			mqdes;
      size_t			msg_len;
      unsigned int		msg_prio;
      struct timespec		abs_timeout;
    } mq_sendrecv;
    struct {
      int			oflag;
      mode_t			mode;
      struct mq_attr		attr;
    } mq_open;
    struct {
      pid_t			pid;
      struct audit_cap_data	cap;
    } capset;
  };
  int fds[2];

#if AUDIT_DEBUG
  int		    put_count;
  int		    ino_count;
#endif
};

// End of Stuff from auditsc.c
//=============================================================================

static void print_sha256(const unsigned char sha256[32])
{
  printk( KERN_INFO "NBH SHA256: "
      "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
      "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
      "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
      "%02x%02x\n",
      sha256[0], sha256[1], sha256[2], sha256[3], sha256[4],
      sha256[5], sha256[6], sha256[7], sha256[8], sha256[9],
      sha256[10], sha256[11], sha256[12], sha256[13], sha256[14],
      sha256[15], sha256[16], sha256[17], sha256[18], sha256[19],
      sha256[20], sha256[21], sha256[22], sha256[23], sha256[24],
      sha256[25], sha256[26], sha256[27], sha256[28], sha256[29],
      sha256[30], sha256[31] );
}        

/*
 * Updates SHA256 with fields from syscall record.
 *
 * int            4    syscall
 * int            4    success
 * long           8    exit
 * unsigned long  8    a1
 * unsigned long  8    a2
 * int            4    items
 * pid_t          4    pid
 * uid_t          4    uid
 * gid_t          4    gid
 * uid_t          4    euid
 * uid_t          4    suid
 * gid_t          4    egid
 * gid_t          4    sgid
 * char[16]       16   comm
 * char[PATH_MAX] 4096 exe
 *
 * In total, we'll need at most 10*4 + 3*8 + 16 + 4096 = 4176 bytes
 * to store field values.
 *
 * Returns -1 on error, 0 otherwise.
 * */
int dedup_sha256_update_syscall(
    sha2_context*         sha256_ctx,
    struct audit_context* audit_ctx,
    struct task_struct*   tsk,
    gfp_t                 gfp_mask )
{
  unsigned char* buf;

  size_t nb;
  size_t nbytes = 0;

  /* for comm */
  char name[sizeof(tsk->comm)];

  /* for exe */
  struct mm_struct *mm = tsk->mm;
  struct vm_area_struct *vma;
  char *p, *pathname;

  buf = kmalloc( sizeof(audit_ctx->major) +
      sizeof(audit_ctx->return_valid) +
      sizeof(audit_ctx->return_code) +
      sizeof(audit_ctx->argv[1]) +
      sizeof(audit_ctx->argv[2]) +
      sizeof(audit_ctx->name_count) +
      sizeof(audit_ctx->pid) +
      sizeof(audit_ctx->uid) +
      sizeof(audit_ctx->gid) +
      sizeof(audit_ctx->euid) +
      sizeof(audit_ctx->suid) +
      sizeof(audit_ctx->egid) +
      sizeof(audit_ctx->sgid) +
      sizeof(char[sizeof(tsk->comm)]) +
      PATH_MAX * sizeof(char) , gfp_mask );
  if (!buf) {
    printk( KERN_WARNING "NBH syscall: out-of-memory" );
    return -1;
  }

  /* syscall */
  nb = sizeof(audit_ctx->major);
  memcpy( &buf[nbytes], &(audit_ctx->major), nb);
  nbytes += nb;

  /* success */
  nb = sizeof(audit_ctx->return_valid);
  memcpy( &buf[nbytes], &(audit_ctx->return_valid), nb );
  nbytes += nb;

  /* exit */
  nb = sizeof(audit_ctx->return_code);
  memcpy( &buf[nbytes], &(audit_ctx->return_code), nb );
  nbytes += nb;

  /* a1 */
  nb = sizeof(audit_ctx->argv[1]);
  memcpy( &buf[nbytes], &(audit_ctx->argv[1]), nb );
  nbytes += nb;

  /* a2 */
  nb = sizeof(audit_ctx->argv[2]);
  memcpy( &buf[nbytes], &(audit_ctx->argv[2]), nb );
  nbytes += nb;

  /* items */
  nb = sizeof(audit_ctx->name_count);
  memcpy( &buf[nbytes], &(audit_ctx->name_count), nb );
  nbytes += nb;

  /* pid */
  nb = sizeof(audit_ctx->pid);
  memcpy( &buf[nbytes], &(audit_ctx->pid), nb );
  nbytes += nb;

  /* uid */
  nb = sizeof(audit_ctx->uid);
  memcpy( &buf[nbytes], &(audit_ctx->uid), nb );
  nbytes += nb;

  /* gid */
  nb = sizeof(audit_ctx->gid);
  memcpy( &buf[nbytes], &(audit_ctx->gid), nb );
  nbytes += nb;

  /* euid */
  nb = sizeof(audit_ctx->euid);
  memcpy( &buf[nbytes], &(audit_ctx->euid), nb );
  nbytes += nb;

  /* suid */
  nb = sizeof(audit_ctx->suid);
  memcpy( &buf[nbytes], &(audit_ctx->suid), nb );
  nbytes += nb;

  /* egid */
  nb = sizeof(audit_ctx->egid);
  memcpy( &buf[nbytes], &(audit_ctx->egid), nb );
  nbytes += nb;

  /* sgid */
  nb = sizeof(audit_ctx->sgid);
  memcpy( &buf[nbytes], &(audit_ctx->sgid), nb );
  nbytes += nb;

  /* comm */
  get_task_comm(name, tsk);
  nb = strlen(name);
  memcpy( &buf[nbytes], name, nb );
  nbytes += nb;

  /* exe */
  if (mm) {
    down_read(&mm->mmap_sem);
    vma = mm->mmap;
    while (vma) {
      if ((vma->vm_flags & VM_EXECUTABLE) &&
          vma->vm_file) {
        pathname = kmalloc(PATH_MAX, gfp_mask);
        if (!pathname) {
          printk(KERN_WARNING "NBH syscall: <no_memory>\n");
          kfree( buf );
          return -1;
        }
        else
        {
          p = d_path(&vma->vm_file->f_path, pathname, PATH_MAX);
          if (IS_ERR(p)) {
            printk(KERN_WARNING "NBH syscall: <too_long\n>");
            kfree(pathname);
            kfree(buf);
            return -1;
          }
          else {
            nb = strlen(p) * sizeof(char);
            memcpy( &buf[nbytes], p, nb );
            nbytes += nb;
          }
          kfree(pathname);
        }
        break;
      }
      vma = vma->vm_next;
    }
    up_read(&mm->mmap_sem);
  }

  sha2_update( sha256_ctx, buf, nbytes );
  kfree( buf );
  return 0;
}

/*
 * Updates SHA256 with fields from cwd record.
 *
 * Returns -1 on error, 0 otherwise.
 * */
int dedup_sha256_update_cwd(
    sha2_context*         sha256_ctx,
    struct audit_context* audit_ctx,
    gfp_t                 gfp_mask )
{
  char *p, *pathname;
  pathname = kmalloc(PATH_MAX, gfp_mask);
  if (!pathname) {
    printk( KERN_WARNING "NBH cwd: <no_memory>" );
    return -1;
  }
  p = d_path(&audit_ctx->pwd, pathname, PATH_MAX);
  if (IS_ERR(p)) { /* Should never happen since we send PATH_MAX */
    /* FIXME: can we save some information here? */
    printk( KERN_WARNING  "NBH cwd: <too_long>" );
    kfree(pathname);
    return -1;
  } else
    sha2_update( sha256_ctx, p, strlen(p) * sizeof(char) );

  kfree(pathname);
  return 0;
}

int dedup_sha256_update_path(
    sha2_context*         sha256_ctx,
    int                   item,
    struct audit_context* audit_ctx,
    struct audit_names*   n,
    gfp_t                 gfp_mask)
{
  unsigned char* buf;
  size_t nb;
  size_t nbytes = 0;
  char *p, *pathname;

  buf = kmalloc( sizeof(item) + (PATH_MAX * sizeof(char)) +
      sizeof(n->ino) + sizeof(n->mode) + sizeof(n->uid) + sizeof(n->gid),
      gfp_mask );
  if (!buf)
  {
    printk( KERN_WARNING "NBH path: out-of-memory!");
    return -1;
  }

  /* item */
  nb = sizeof(item);
  memcpy( &buf[nbytes], &item, nb );
  nbytes += nb;

  /* name */

  if (n->name) {
    switch(n->name_len) {
      case AUDIT_NAME_FULL:
        /* full path */
        nb = strlen(n->name) * sizeof(char);
        memcpy( &buf[nbytes], n->name, nb );
        nbytes += nb;
        break;
      case 0:
        /* name was specified as a relative path and the
         * directory component is the cwd */

        pathname = kmalloc(PATH_MAX, gfp_mask);
        if (!pathname) {
          printk( KERN_WARNING "NBH path: <no_memory>" );
          return -1;
        }
        p = d_path(&audit_ctx->pwd, pathname, PATH_MAX);
        if (IS_ERR(p)) { /* Should never happen since we send PATH_MAX */
          /* FIXME: can we save some information here? */
          printk( KERN_WARNING "NBH path: <too_long>" );
          kfree( pathname );
          kfree( buf );
          return -1;
        } else {
          nb = strlen(p);
          memcpy( &buf[nbytes], p, nb );
          nbytes += nb;
        }
        kfree(pathname);
        break;
      default:
        /* log the name's directory component */
        nb = n->name_len;
        memcpy( &buf[nbytes], n->name, nb );
        nbytes += nb;
    }
  } else {
    buf[nbytes++] = 0x0;
  }

  /* inode */
  nb = sizeof(n->ino);
  memcpy( &buf[nbytes], &n->ino, nb );
  nbytes += nb;

  /* mode */
  nb = sizeof(n->mode);
  memcpy( &buf[nbytes], &n->mode, nb );
  nbytes += nb;

  /* ouid */
  nb = sizeof(n->uid);
  memcpy( &buf[nbytes], &n->uid, nb );
  nbytes += nb;

  /* ogid */
  nb = sizeof(n->gid);
  memcpy( &buf[nbytes], &n->gid, nb );
  nbytes += nb;

  sha2_update( sha256_ctx, buf, nbytes );
  kfree( buf );
  return 0;
}

/*
 * Updates SHA256 with fields from path records. The number of path records
 * is specified by audit_ctx->name_count.
 *
 * int            4     item
 * char[PATH_MAX] 4096  name
 * unsigned long  8     inode
 * umode_t        2     mode
 * uid_t          4     ouid
 * gid_t          4     ogid
 *
 * Returns -1 on error, 0 otherwise.
 * */
int dedup_sha256_update_paths(
    sha2_context*         sha256_ctx,
    struct audit_context* audit_ctx,
    gfp_t                 gfp_mask )
{
  int i;
  for (i = 0; i < audit_ctx->name_count; i++) {
    struct audit_names *n = &audit_ctx->names[i];
    if (n->ino == (unsigned long)-1) return -1;
    if ( dedup_sha256_update_path(sha256_ctx, i, audit_ctx, n, gfp_mask) == -1 )
      return -1;
  }
  return 0;
}


/*
 * Finds duplicate events.
 *
 * Returns false if calling function should not proceed.
 * */
bool dedup( struct audit_context* audit_ctx, struct task_struct* tsk, gfp_t gfp_mask )
{
  //static int nnew = 0, ndup = 0;
  sha2_context sha256_ctx;
  unsigned char sha256_out[32];

  /*----------------------------
   *  Sanity checks
   *-------------------------- */

  /* Only care about open or execve */
  if (audit_ctx->major != __NR_open &&
      audit_ctx->major != __NR_execve)
    return true;

  /* Sanity for syscall */
  if (!audit_ctx->return_valid)
    return true;

  /* Sanity for cwd */
  if (!audit_ctx->pwd.dentry || !audit_ctx->pwd.mnt)
    return true;

  /* --- End of Sanity Checks --- */


  sha2_starts( &sha256_ctx, 0 );

  if (dedup_sha256_update_syscall( &sha256_ctx, audit_ctx, tsk, gfp_mask ) == -1)
  {
    sha2_finish( &sha256_ctx, sha256_out);
    return true;
  }

  if (dedup_sha256_update_cwd( &sha256_ctx, audit_ctx, gfp_mask ) == -1 )
  {
    sha2_finish( &sha256_ctx, sha256_out);
    return true;
  }

  if (dedup_sha256_update_paths( &sha256_ctx, audit_ctx, gfp_mask ) == -1 )
  {
    sha2_finish( &sha256_ctx, sha256_out);
    return true;
  }

  sha2_finish( &sha256_ctx, sha256_out);
  //print_sha256( sha256_out );

  if (ddst_has_sha1(sha256_out) == false)
  {
    ddst_insert_sha1(sha256_out, gfp_mask);
    //printk( KERN_INFO "NBH Not duplicated.\n" );
    //nnew++;
    //if (((ndup + nnew) % 10000) == 0)
    //  printk( KERN_INFO "NBH: 1 total %d duplicated %d\n",
    //      (ndup + nnew), ndup );
    return true;
  }
  else
  {
    //if (debug_target == 1)
    //  printk( KERN_INFO "NBH Duplicated" );
    //ndup++;
    //if (((ndup + nnew) % 10000) == 0)
    //  printk( KERN_INFO "NBH: 2 total %d duplicated %d\n",
    //      (ndup + nnew), ndup );
    return false;
  }

  // Check if we should be concerned about this context
  // We only want syscall=open and syscall=execve
  return true;
}

#else

void dd_printf (const char * format, ...)
{
  FILE* f = fopen("/home/bengheng/mylog.log", "a");
  if (f == NULL)
  {
    printf("Cannot open mylog.log\n");
    return;
  }
  va_list args;
  va_start (args, format);
  vfprintf (f, format, args);
  va_end (args);
  fflush(f);
  fclose(f);
}

//--------------------------------------------------------------------

static void dd_fprintf_worker(
    FILE* log_file,
    struct auditd_reply_list* rep )
{
  Element* e;
  int rc;
  int i;

  //dd_printf("WRK: [%s]\n", rep->reply.msg.data);

  rc = dd_update_event( &e, log_file, rep );
  if ( rc == -1 ) {
    //dd_printf("Event Update Error\n");
    fprintf( log_file, "%s\n", rep->reply.msg.data );
    free( rep );
    return;
  }
  else if ( rc == 1 ) {
    // Event is complete.

    // If the signature is not duplicated, we can now distribute
    // all the reps. Otherwise, simply free reps.
    //if (dd_has_sig( e->sha1 ) == false) {
    if (ddst_has_sha1( e->sha1 ) == false) {
      // Not duplicated.
      //dd_printf( "%d: Not duplicated.\n", e->seq_num );

      // Add signature and distribute.
      //dd_add_sig( e->sha1 );
      ddst_insert_sha1( e->sha1 );
      //dd_printf( "%d: Added sig.\n", e->seq_num );

      dd_fprintf_internal( e );
    }
    else {
      // Duplicated. Remove event. 
      //dd_printf( "%d: Duplicated. [%s]\n",
      //   e->seq_num, e->reps[RT_PATH2] == NULL ?
      //    e->reps[RT_PATH1]->reply.msg.data
      //   : e->reps[RT_PATH2]->reply.msg.data );
      dd_remove_event( e ); 
    }
  }
  else
  {
    //dd_printf("Event Incomplete\n");
  }
}


#ifdef DEDUP_MT

typedef struct _Work
{
  FILE* log_file;
  struct auditd_reply_list* rep;
} Work;

#define WORK_BUFFER_SIZE 10000000
static Work work_buffer[WORK_BUFFER_SIZE];
static int work_head = 0;
static int work_tail = 0;

static pthread_mutex_t  mutex;
static sem_t            full;
static sem_t            empty;
static pthread_t        work_thread;

static Work* get_work()
{
  Work* w = &work_buffer[ work_head ];
  work_head++;
  work_head = work_head % WORK_BUFFER_SIZE;
  return w;
}

static put_work(
    FILE*                     log_file,
    struct auditd_reply_list* rep )
{
  work_buffer[ work_tail ].log_file = log_file;
  work_buffer[ work_tail ].rep      = rep;
  work_tail++;
  work_tail = work_tail % WORK_BUFFER_SIZE;
}


void* dd_thread( void* ptr )
{
  Work* w;

  while (true)
  {
    sem_wait( &full );
    pthread_mutex_lock( &mutex );

    w = get_work();
    if (w->log_file == NULL) 
    {
      pthread_mutex_unlock( &mutex );
      sem_post( &empty );
      break;
    }

    pthread_mutex_unlock( &mutex );
    sem_post( &empty );

    dd_fprintf_worker( w->log_file, w->rep );
  }
  pthread_exit( NULL );
}
#endif



int dd_fprintf(
    FILE*       log_file,
    struct auditd_reply_list* rep )
{
  // rep could be deleted, so we store the return code first.
  int rc = strlen(rep->reply.msg.data) + 1;
 
#ifdef DEDUP_MT
  sem_wait( &empty );
  pthread_mutex_lock( &mutex );
  put_work( log_file, rep );
  pthread_mutex_unlock( &mutex );
  sem_post( &full );
#else
  dd_fprintf_worker( log_file, rep );
#endif
  return rc;
}

//--------------------------------------------------------------------


/*
 * Initialization.
 * */
void dd_init()
{
  dd_init_events();
  //dd_init_sigs();
  ddst_init();
  //dd_printf("DEBUG 1: Init done.\n");

#ifdef DEDUP_MT
  pthread_mutex_init( &mutex, NULL );
  sem_init( &full, 0, 0 );
  sem_init( &empty, 0, WORK_BUFFER_SIZE );
  pthread_create( &work_thread, NULL, dd_thread, NULL );
#endif
}

/*
 * Destruction.
 *  */
void dd_destroy()
{
#ifdef DEDUP_MT
  dd_fprintf( NULL, NULL, 0 );
  pthread_join( work_thread, NULL );
  pthread_mutex_destroy( &mutex );
  sem_destroy( &full );
  sem_destroy( &empty );
#endif
  //dd_printf("DEBUG 2: dedup shutting down.\n");

  dd_destroy_events();
  //dd_destroy_sigs();
  ddst_destroy();
}

#endif // __KERNEL__
