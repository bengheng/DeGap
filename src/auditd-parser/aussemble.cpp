
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#ifdef USE_AUREAD
#include "auread.h"
#else
#include <auparse.h>
#include <libaudit.h>
#endif
#include <boost/foreach.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <pthread.h>
#include <semaphore.h>
//#include <google/heap-profiler.h>
#include <set>
#include <list>
#include <algorithm>
#include <unordered_map>
#include "process.h"
#include "file.h"
#include "syscall.h"
#include "aumake.h"
#include "utilities.h"
#include "strhash.h"
#include "auwork.h"

using namespace std;
using namespace boost::filesystem;
using namespace boost::algorithm;

typedef struct
{
  bool              done;
  strlut_t          *strlut;
  list<PEVENT>      asm_work;
  list<PEVENT>      rej_work;
  File              *rootfile;
  pthread_cond_t    cond;
  pthread_cond_t    rejects_cond;
  pthread_mutex_t   mutex;
  pthread_mutex_t   strlut_mutex;
  pthread_mutex_t   rejects_mutex; 
  pthread_mutex_t   process_mutex;
  pthread_mutex_t   rootfile_mutex;
} ASSEMBLE_CTX;

/*!
 * Assemble consumer thread.
 * */
void *assemble_consumer(void *ptr)
{
  ASSEMBLE_CTX *ctx = (ASSEMBLE_CTX*) ptr;
  PEVENT pevt;

  while (true)
  {
    // wait for work...
    pthread_mutex_lock(&(ctx->mutex));
    while (ctx->asm_work.empty() && ctx->done == false)
    { pthread_cond_wait(&(ctx->cond), &(ctx->mutex)); }

    if (ctx->asm_work.empty() && ctx->done == true)
    {
      pthread_mutex_unlock(&(ctx->mutex));
      break;
    }

    pevt = ctx->asm_work.front();
    ctx->asm_work.pop_front();
    pthread_mutex_unlock(&(ctx->mutex));

    //
    // do work
    //

    pthread_mutex_lock(&(ctx->process_mutex));
    pevt->process->addSyscall(pevt->serial, pevt->syscall);
    pthread_mutex_unlock(&(ctx->process_mutex));

    pevt->syscall->setProcess(pevt->process);

    pair<hash_t, list<FileInstance*>* > p;
    BOOST_FOREACH(p, pevt->file_instances)
    {
      path name;

      pthread_mutex_lock(&(ctx->strlut_mutex));
      // Prepare full path
      if ((*(ctx->strlut))[p.first] == NULL)
      {
        pair <hash_t, char*> p;
        BOOST_FOREACH(p, *(ctx->strlut))
        { fprintf(stderr, "DEBUG %lu %s\n", p.first, p.second); }
        fprintf(stderr, "DEBUG FATAL %lu\n", p.first);
      }
      name = (*(ctx->strlut))[p.first];
      pthread_mutex_unlock(&(ctx->strlut_mutex));


      path fullpath = ( name.is_relative() ? pevt->cwd / name : name );
      fullpath.normalize();
      if (fullpath.filename() == string("."))
        fullpath = fullpath.parent_path();

      // Tokenize full path
      list<hash_t> hashlist;
      size_t l = fullpath.string().length();
      char *s = new char[l + 1];
      strncpy(s, fullpath.string().c_str(), l + 1);

      pthread_mutex_lock(&(ctx->strlut_mutex));
      splitPathToHashList(*(ctx->strlut), s, "/", hashlist);
      hash_t fullpath_hash = getStrHash(*(ctx->strlut), fullpath.string().c_str());
      hash_t parpath_hash  = getStrHash(*(ctx->strlut), fullpath.parent_path().c_str());
      pthread_mutex_unlock(&(ctx->strlut_mutex));

      delete [] s;
      list<hash_t>::iterator hashlist_itr = hashlist.begin();

      //fprintf(stderr, "[+] Adding [%08x] %s\n", fullpath_hash, fullpath.string().c_str());
      pthread_mutex_lock(&(ctx->rootfile_mutex));
      ctx->rootfile->addFileInstances(hashlist.end(), hashlist_itr, NULL,
          fullpath_hash, parpath_hash, *p.second, pevt->syscall, 0);
      pthread_mutex_unlock(&(ctx->rootfile_mutex));

      delete p.second;
    }
    delete pevt;
  }

  pthread_exit(NULL);
}

/*!
 * Assemble reject thread.
 * */
void *assemble_reject(void *ptr)
{
  ASSEMBLE_CTX *ctx = (ASSEMBLE_CTX*) ptr;
  PEVENT pevt;

  while (true)
  {
    // wait for reject...
    pthread_mutex_lock(&(ctx->rejects_mutex));
    while (ctx->rej_work.empty() && ctx->done == false)
    { pthread_cond_wait(&(ctx->rejects_cond), &(ctx->rejects_mutex)); }
    if (ctx->rej_work.empty() && ctx->done == true)
    {
      pthread_mutex_unlock(&(ctx->rejects_mutex));
      break;
    }
    pevt = ctx->rej_work.front();
    ctx->rej_work.pop_front();
    pthread_mutex_unlock(&(ctx->rejects_mutex));

    serial_t serial = pevt->serial;

    // Can't delete process because there might be multiple
    // pevts pointing to the same process.
    // Will result in double-free.

    // Delete file instances if there are no attached syscalls.
    if (pevt->syscall != NULL) delete pevt->syscall;
    pair<long, list<FileInstance*>* > p;
    BOOST_FOREACH(p, pevt->file_instances)
    {
      BOOST_FOREACH(FileInstance *fi, *p.second)
      { if (fi->getNumSyscalls() == 0) delete fi; }
      delete p.second;
    }

    delete pevt;
  }
}

/*!
 * Assembles all the relationships.
 * */
void assemble(
    const int nprocs,
    strlut_t &strlut,
    list<PEVENT> &events,
    set<Syscall*> &syscalls,
    File &rootfile)
{
  int rc;
  size_t rejects = 0;

  ASSEMBLE_CTX ctx;
  ctx.done           = false;
  ctx.strlut         = &strlut;
  ctx.rootfile       = &rootfile;
  ctx.cond           = PTHREAD_COND_INITIALIZER;
  ctx.rejects_cond   = PTHREAD_COND_INITIALIZER;
  ctx.mutex          = PTHREAD_MUTEX_INITIALIZER;
  ctx.strlut_mutex   = PTHREAD_MUTEX_INITIALIZER;
  ctx.rejects_mutex  = PTHREAD_MUTEX_INITIALIZER;
  ctx.process_mutex  = PTHREAD_MUTEX_INITIALIZER;
  ctx.rootfile_mutex = PTHREAD_MUTEX_INITIALIZER; 
  //sem_init(&(ctx.empty), 0, 4);
  //sem_init(&(ctx.full), 0, 0);

  // Create 4 consumer threads
  pthread_t asm_threads[nprocs];
  for (int i = 0; i < nprocs; ++i)
  {
    rc = pthread_create(&asm_threads[i],
        NULL, assemble_consumer, (void*) &ctx);
    assert(rc == 0);
  }

  // Create reject thread
  pthread_t rej_thread;
  rc = pthread_create(&rej_thread, NULL, assemble_reject, (void*)&ctx);
  assert(rc == 0);

  // For each event...
  list<PEVENT>::iterator evts_itr = events.begin();
  while (evts_itr != events.end())
  {
    PEVENT e = *evts_itr;
    serial_t serial = e->serial;


    //fprintf(stderr, "DEBUG %08x process %08x syscall %08x file_instances.size() %zu\n",
    //    pevt, pevt->process, pevt->syscall, pevt->file_instances.size());

    // Reject incomplete events.
    if (e->process == NULL ||
        e->syscall == NULL ||
        e->bad == true /*||
        e->syscall->getSuccess() == false*/)
    {
      ++rejects;

      //fprintf(stderr, "Reject process %x syscall %x bad %d success %d\n",
      //    e->process, e->syscall, e->bad,
      //    e->syscall == NULL ? -1 : e->syscall->getSuccess());

      pthread_mutex_lock(&(ctx.rejects_mutex));
      ctx.rej_work.push_back(e);
      pthread_cond_signal(&(ctx.rejects_cond));
      pthread_mutex_unlock(&(ctx.rejects_mutex));

      //evt_list->erase(evts_itr++);
      evts_itr++;
      continue;
    }

    // Save syscall pointers for future removal
    if (e->syscall != NULL)
      syscalls.insert(e->syscall);

    // Put work into list
    pthread_mutex_lock(&(ctx.mutex));
    ctx.asm_work.push_back(e); // queue work
    pthread_cond_signal(&(ctx.cond));
    pthread_mutex_unlock(&(ctx.mutex));

    ++evts_itr;
  }
  pthread_mutex_lock(&(ctx.mutex));
  pthread_mutex_lock(&(ctx.rejects_mutex));
  ctx.done = true;
  pthread_cond_broadcast(&(ctx.cond));
  pthread_cond_broadcast(&(ctx.rejects_cond));
  pthread_mutex_unlock(&(ctx.rejects_mutex));
  pthread_mutex_unlock(&(ctx.mutex));

  // Wait for consumer threads...
  for (int i = 0; i < nprocs; ++i)
  {
    int rc = pthread_join(asm_threads[i], NULL);
    assert(rc == 0);
  }

  // Wait for reject thread...
  rc = pthread_join(rej_thread, NULL);
  assert(rc == 0);

  // Destroy sync objects
  pthread_cond_destroy(&(ctx.cond));
  pthread_cond_destroy(&(ctx.rejects_cond));
  pthread_mutex_destroy(&(ctx.mutex));
  pthread_mutex_destroy(&(ctx.strlut_mutex));
  pthread_mutex_destroy(&(ctx.rejects_mutex));
  pthread_mutex_destroy(&(ctx.process_mutex));
  pthread_mutex_destroy(&(ctx.rootfile_mutex)); 
  //sem_destroy(&(ctx.full));
  //sem_destroy(&(ctx.empty));

  fprintf(stderr, "DEBUG %d rejects\n", rejects);
}

