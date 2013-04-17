#ifndef __DEDUP_RECORD_HEADER__
#define __DEDUP_RECORD_HEADER__

#include <stdbool.h>
#include <stdio.h>
#include <openssl/sha.h>
#include "avltree.h"
#include "dedup.h"

typedef enum {
  RT_SYSCALL = 0,
  RT_EXECVE,
  RT_CWD,
  RT_PATH1,
  RT_PATH2
} RECORD_TYPE;


struct Element {
  unsigned long             seq_num;  // Sequence number. Also used as key for AVL tree
  int                       items;    // number of Paths
  //unsigned long             hash;     // cumulative hash of all messages avail so far
  unsigned char             sha1[SHA_DIGEST_LENGTH];
  FILE*                     log_file;
  //int                       types[5];
  struct auditd_reply_list* reps[5];
  struct Element*           next_unused;
};


int   dd_init_events();
int   dd_update_event( Element** e, FILE* log_file, struct auditd_reply_list* rep );
void  dd_remove_event( Element* e );
void  dd_fprintf_internal( Element* e);
void  dd_destroy_events();

#endif
