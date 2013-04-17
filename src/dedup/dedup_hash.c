/*
 * dedup_hash.c
 *
 * Functions for computing string hash and sieving strings (removing
 * unwanted field values).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <openssl/sha.h> // for sha1()

#include "libaudit.h"

#include "dedup.h"

/*
 * Fields whose values matter in determining the signature
 * of the messages.
 */

/*
 * We're lazy and just want a string hash function that works. If hash is
 * specified as an argument to the function, we'll use that. This allows
 * us to chain hashes together.
 *
 * Otherwise, the default value of 5381 is used. See dedup_hash.h.
 *
 * http://www.cse.yorku.ca/~oz/hash.html
 * */
unsigned long dd_hash(const char *str)
{
  int c;
  unsigned long hash = 5381;
  while (c = *str++)
    hash = ((hash << 5) + hash) ^ c; /* hash * 33 ^ c */

  return hash;
}

static bool syscall_ok[25] =
{ false,  // arch
  true,   // syscall
  true,   // success
  true,   // exit
  false,  // a0
  true,   // a1
  true,   // a2
  false,  // a3
  true,   // items
  false,  // ppid
  true,   // pid
  false,  // auid
  true,   // uid
  true,   // gid
  true,   // euid
  true,   // suid
  false,  // fsuid
  true,   // egid
  true,   // sgid
  false,  // fsgid
  false,  // tty
  false,  // ses
  true,   // comm
  true,   // exe
  false,  // key
};

static bool cwd_ok[1] = { true }; // cwd

static bool path_ok[8] =
{ false,  // item
  true,   // name
  true,   // inode
  false,  // dev
  true,   // mode
  true,   // ouid
  true,   // ogid
  false   // rdev
};

inline bool is_syscall_field( const int i ) { return syscall_ok[i]; }
inline bool is_path_field( const int i )    { return path_ok[i];    }
inline bool is_cwd_field( const int i )     { return cwd_ok[i];     }
inline bool is_execve_field( const int i )  { return false;         }
inline bool is_other_field( const int i )   { return false;         }

typedef bool (*is_field_ok) ( const int i );

/*
 * This is the combined version of dd_sieve and dd_hash. It computes the
 * hash on characters we're interested in.
 * */
unsigned long dd_sieve_hash(
    const char *ins,
    //int len,
    const int type)
{
  register char c;
  //const char* f;
  int i = 0;
  is_field_ok is_ok;
  unsigned long hash = 5381;

  // Stir record type into hash... will this work... ?
  hash = ((hash << 5) + hash) ^ type;

  switch (type)
  {
    case AUDIT_SYSCALL: is_ok = is_syscall_field;  break;
    case AUDIT_CWD:     is_ok = is_cwd_field;      break;
    case AUDIT_PATH:    is_ok = is_path_field;     break;
    case AUDIT_EXECVE:  is_ok = is_execve_field;   break;
    default: is_ok = is_other_field;
  }

  // ins begins in a format similar to the following:
  //     "type=CWD audit(1346946433.615:13):  cwd=...."
  // So we need to go past the first two fields that we don't use.
  //f = ins;
  //while (*ins++ != ' ');
  //while (*ins++ == ' ');
  while (*ins++ != ' ');
  while (*ins++ == ' ');

  --ins; // need to compensate by 1
  //len -= (ins - f);

  while (/*len != -1*/*ins != 0x0)
  {
    //printf("*** %d %s***\n", len, ins);

    // Gobble field characters
    //f = ins;
    while ((c = *ins++) != '=')
    {
      hash = ((hash << 5) + hash) ^ c;
    }
    //len -= (ins - f);

    // Gobble value characters
    //printf("Checking \"%s\"\n", f);
    if ( is_ok( i++ ) == true )
    {
      // with hash computation
      while ( /*(len-- != 0)*/ (*ins != 0x0) && ((c = *ins++) != ' ') )
      {
        //printf("[+] \'%c\' %d\n", c, len);
        hash = ((hash << 5) + hash) ^ c;
      }
    }
    else {
      while ( /*(len-- != 0)*/ (*ins != 0x0) && ((c = *ins++) != ' ') );
      //{
      //printf("[-] \'%c\' %d\n", c, len);
      //}
    }
    //dd_printf("--- %d ---\n", len);
  }
  return hash;
}

//=============================================================================

/*
 * Computes SHA1 for sieved ins.
 * */
void dd_sieve_sha1( const char* ins, const int type, SHA_CTX* sha_ctx )
{
  register char c;
  register unsigned int n = 0;
  int i = 0;
  is_field_ok is_ok;
  unsigned char sieve[MAX_AUDIT_MESSAGE_LENGTH + sizeof(int)];
  unsigned char *s = sieve;

  dd_printf( "HSHI: [%s]\n", ins );

  // Stir record type into hash... will this work... ?
  memcpy( s, &type, sizeof(int) );
  s += sizeof(int);
  
  switch (type)
  {
    case AUDIT_SYSCALL: is_ok = is_syscall_field;  break;
    case AUDIT_CWD:     is_ok = is_cwd_field;      break;
    case AUDIT_PATH:    is_ok = is_path_field;     break;
    case AUDIT_EXECVE:  is_ok = is_execve_field;   break;
    default: is_ok = is_other_field;
  }

  // ins begins in a format similar to the following:
  //     "type=CWD audit(1346946433.615:13):  cwd=...."
  // So we need to go past the first two fields that we don't use.
  // We know we can skip at least 37 characters because the shortest
  // prefix will be something like the following:
  // type=CWD msg=audit(0123456789.012:1):
  ins += 37;
  //while (*ins++ != ' ');
  //while (*ins++ == ' ');
 
 // Unfortunately, we need to check for NULL on every iteration
 // because there can be a weird case such as the following: 
 // "type=EXECVE msg=audit(1335921323.848:16043268):"
  while (*ins != 0x0 && *ins++ != ' ');
  while (*ins != 0x0 && *ins++ == ' ');
  if (*ins != 0x0) --ins; // need to compensate by 1

  while (*ins != 0x0)
  {
    // Gobble field characters
    do{
      c = *ins++;
      *s++ = c;
      n++;
    } while (c != '=');

    // Gobble value characters
    if ( is_ok( i++ ) == true )
    {
      while ( ((c = *ins) != ' ') && (c != 0x0) )
      {
        *s++ = c;
        ins++;
        n++;
      }
    }
    else
    {
      while ( ((c = *ins) != ' ') && (c != 0x0) ) { ins++; };
    }
  }

  //printf("[%s]\n", &sieve[sizeof(int)]);
  SHA1_Update( sha_ctx,
      sieve,
      sizeof(unsigned int) + n );
  dd_printf( "HSHO: [%s]\n", &sieve[sizeof(int)] );

}
