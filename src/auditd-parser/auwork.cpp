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

using namespace std;
using namespace boost::filesystem;
using namespace boost::algorithm;


/*!
 * Create process object. If another program with the same comm and exe
 * does not already exist, one is created and appended to progs.
 *
 * Returns pointer to new or existing prog. Returns NULL on error.
 * */
Process * createProcess(
    strlut_t& strlut,
    pthread_mutex_t* strlut_mutex,
    ProgFile &rootprog,
    const char *comm,
    const char *exe,
    pid_t ppid,
    pid_t pid)
{
  Program     *prog   = NULL;
  Program     *pprog  = NULL;
  Process     *proc   = NULL;
  Process     *pproc  = NULL;

  // Re-use program if one with same comm and exe already exists.
  // Otherwise create a new one.

  list< hash_t > hashlist;
  char *s = allocCpyStrNoQuotes( exe );
  assert( s != NULL );

  // Make a copy of exe without quotes
  int l = strlen(s);
  assert(l != 0);
  char* e = new char[l+1];
  strcpy(e, s);

  // Make a copy of comm without quotes
  char *c = allocCpyStrNoQuotes( comm );
  assert( c != NULL );

  pthread_mutex_lock( strlut_mutex );  
  //fprintf( stderr, "DEBUG s %s c %s e %s\n", s, c, e );
  splitPathToHashList(strlut, s, "/", hashlist);
  hash_t comm_hash = getStrHash(strlut, c);
  hash_t exe_hash  = getStrHash(strlut, e);
  pthread_mutex_unlock( strlut_mutex );
  delete [] s;
  delete [] e;
  delete [] c;

  list< hash_t >::iterator hashlist_itr = hashlist.begin();
  prog = rootprog.addProgram(
      hashlist.end(), hashlist_itr,
      comm_hash, exe_hash);

  proc = prog->mkProcess(pid);

  if (pid != ppid)
  {

    // If a program has a process with the same ppid exists, we use that as the
    // parent. Otherwise, create a new program.  This may actually be wrong for
    // non-daemon processes because pids can be re-cycled. However, since we're
    // more concerned with services, which would be persistent, this should be
    // ok.

    pproc = rootprog.getProcess(ppid);
    if (pproc != NULL)
    {
      pprog = pproc->getInstanceOf();
    }
    else
    {
      //
      // Can't create parent with comm and exe.
      // We don't have that information.
      //

      // The hash for "" is known and would have been added to strlut already,
      // so we add the hashes manually to avoid locking strlut_mutex. 

      list< hash_t > hashlist2;
      hashlist2.push_back( HASH_0 );
      list< hash_t >::iterator hashlist2_itr = hashlist2.begin();

      pprog = rootprog.addProgram(
          hashlist2.end(),
          hashlist2_itr,
          HASH_0, HASH_0);
      pproc = pprog->mkProcess(ppid);
    }
    proc->addParent(pproc);
    pproc->addChild(proc);
  }

  return proc;
}

/*!
 * Handles AUDIT_SYSCALL record. Creates SCOpen or SCExecve
 * depending on the syscall number and populates it.
 *
 * A process is also created.
 *
 * Returns false on error. (For now, the only error is unsupported
 * syscall number.)
 * */
bool syscallHandler(
    strlut_t& strlut,
    pthread_mutex_t* strlut_mutex,
    auparse_state_t* au,
    const SCNUM& scnum,
    EVENT& e,
    ProgFile& rootprog,
    pthread_mutex_t* rootprog_mutex)
{
  assert(auparse_get_type(au) == AUDIT_SYSCALL);
  //assert(e.syscall == NULL);
  //assert(e.process == NULL);

  //Syscall *sc = NULL; 
  SCOpen *sco = NULL;
  int res;
  char comm[PATH_MAX];
  char exe[PATH_MAX];
  pid_t pid = -1;
  pid_t ppid = -1;

  res = auparse_first_field(au);
  while (res == 1)
  {
    string f = auparse_get_field_name(au);
    switch (f[0])
    {
      case 's':
        if (f.compare("syscall") == 0 &&
            e.syscall == NULL)
        {
          //assert(sc == NULL);
          int sci = auparse_get_field_int(au);
          if (sci == scnum.__NR_open)
          {
            sco = new SCOpen(scnum.__NR_open, e.sec, e.milli, e.serial);
            e.syscall = sco;
          }
          else if (sci == scnum.__NR_execve)
          { e.syscall = new SCExecve(scnum.__NR_execve, e.sec, e.milli, e.serial); }
          else if (sci == scnum.__NR_clone)
          { e.syscall = new SCFork(scnum.__NR_fork, e.sec, e.milli, e.serial); }
          else {
            fprintf(stderr, "Bad syscall number %d\n", sci);
            return false;
          } // bad syscall number
        }
        else if (f.compare("success") == 0)
        { e.syscall->setSuccess(auparse_get_field_str(au)); }
        else if (f.compare("suid") == 0)
        { e.syscall->setSuid(auparse_get_field_int(au)); }
        else if (f.compare("sgid") == 0)
        { e.syscall->setSgid(auparse_get_field_int(au)); }
        break;

      case 'e':
        if (f.compare("exit") == 0)
        { e.syscall->setExit(auparse_get_field_int(au)); }
        else if (f.compare("euid") == 0)
        { e.syscall->setEuid(auparse_get_field_int(au)); }
        else if (f.compare("egid") == 0)
        { e.syscall->setEgid(auparse_get_field_int(au)); }
        else if (f.compare("exe") == 0)
        { strncpy(exe, auparse_get_field_str(au), PATH_MAX); }
        break;

      case 'a':
        if (f.compare("a1") == 0 && sco != NULL)
        { sco->setFlags( convStrToInt(auparse_get_field_str(au), 16) ); }
        else if (f.compare("a2") == 0 && sco != NULL)
        { /* sco->setMode( convStrToInt(auparse_get_field_str(au), 16) ); */ }
        else if (f.compare("auid") == 0)
        { e.syscall->setAuid(auparse_get_field_int(au)); }
        break;

      case 'p':
        if (f.compare("ppid") == 0)
        { ppid = auparse_get_field_int(au); }
        else if (f.compare("pid") == 0) 
        { pid = auparse_get_field_int(au); }
        break;

      case 'u':
        if (f.compare("uid") == 0)
        { e.syscall->setUid(auparse_get_field_int(au)); }
        break;

      case 'g':
        if (f.compare("gid") == 0)
        { e.syscall->setGid(auparse_get_field_int(au)); }
        break;

      case 'f':
        if (f.compare("fsuid") == 0)
        { e.syscall->setFsuid(auparse_get_field_int(au)); }
        else if (f.compare("fsgid") == 0)
        { e.syscall->setFsgid(auparse_get_field_int(au)); }
        break;

      case 'c':
        if (f.compare("comm") == 0)
        { strncpy(comm, auparse_get_field_str(au), PATH_MAX); }
        break;
    }

    res = auparse_next_field(au);
  }

  // Make process
  pthread_mutex_lock(rootprog_mutex);
  e.process = createProcess(strlut, strlut_mutex,
      rootprog, comm, exe, ppid, pid);
  // fprintf(stderr, "Created process %08x\n", e.process);
  pthread_mutex_unlock(rootprog_mutex);
  /*
     e.process->addSyscall(ts->serial, e.syscall);
     e.syscall->setProcess(e.process);
     */
  //e.syscall = sc;

  return true;
}

void execveHandler(auparse_state_t *au, int __NR_execve, EVENT &e)
{
  assert(auparse_get_type(au) == AUDIT_EXECVE);
  //assert(e.syscall != NULL);

  // Allocate syscall if it doesn't exist yet.
  if (e.syscall == NULL)
  {
    e.syscall = new SCExecve(__NR_execve, e.sec, e.milli, e.serial);
  }

  //return; // don't need arguments

  // Sometimes there are 2 entries for EXECVE. Seems
  // that the 2nd entry always contain fewer arguments.
  // So if there is already a first entry, skip the second.
  //
  SCExecve *sc = dynamic_cast<SCExecve *>(e.syscall);
  assert(sc != NULL);
  if (sc->getArgc() == 0)
  {
    const char *f;
    int res = auparse_first_field(au);
    while (res == 1)
    {
      f = auparse_get_field_name(au);

      if (strncmp(f, "argc", 5) == 0)     sc->setArgc(auparse_get_field_int(au));
      else if (strncmp(f, "a0", 5) == 0)  sc->setArg0(auparse_get_field_str(au));
      else if (strncmp(f, "a1", 5) == 0)  sc->setArg1(auparse_get_field_str(au));
      else if (strncmp(f, "a2", 5) == 0)  sc->setArg2(auparse_get_field_str(au));
      else if (strncmp(f, "a3", 5) == 0)  sc->setArg3(auparse_get_field_str(au));

      res = auparse_next_field(au);
    }
  }
}

/*!
 * Extracts information from CWD record.
 * (Actually, there is only 1 field, "cwd".)
 * */
void cwdHandler(auparse_state_t *au, EVENT &e)
{
  assert(auparse_get_type(au) == AUDIT_CWD);

  int res = auparse_first_field(au);
  while (res == 1)
  {
    string f = auparse_get_field_name(au);
    if (f.compare("cwd") == 0)
    {
      //if (!e.cwd.empty())
      //fprintf(stderr, "DEBUG \"%s\", \"%s\"\n",
      //      auparse_get_record_text(au),
      //      e.cwd.c_str());
      assert(e.cwd.empty());
      e.cwd = auparse_get_field_str(au);
      trim_left_if(e.cwd, is_any_of("\""));
      trim_right_if(e.cwd, is_any_of("\""));
    }
    res = auparse_next_field(au);
  }
}

/*!
 * Extracts information from PATH record.
 * */
bool pathHandler(strlut_t& strlut,
    pthread_mutex_t* strlut_mutex,
    auparse_state_t* au,
    EVENT& evt,
    list< string* >& ignore_paths)
{
  assert(auparse_get_type(au) == AUDIT_PATH);
  //assert( !evt.cwd.empty() );

  int inode = -1;
  int ouid = -1;
  int ogid = -1;
  int mode = -1;
  int item = -1;

  string name;
  int res = auparse_first_field(au);
  while (res == 1)
  {
    string f = auparse_get_field_name(au);
    if (f.compare("name") == 0)
    {
      name = auparse_get_field_str(au);
      trim_left_if(name, is_any_of("\""));
      trim_right_if(name, is_any_of("\""));

      if (matchStringList(ignore_paths, name.c_str()))
        return false;
    }
    else if (f.compare("item") == 0)  { item = auparse_get_field_int(au);  }
    else if (f.compare("inode") == 0) { inode = auparse_get_field_int(au); }
    else if (f.compare("ouid") == 0)  { ouid  = auparse_get_field_int(au); }
    else if (f.compare("ogid") == 0)  { ogid  = auparse_get_field_int(au); }
    else if (f.compare("mode") == 0)
    { mode = convStrToInt( auparse_get_field_str(au), 8 ); }
  
    res = auparse_next_field(au);
  }

  pthread_mutex_lock(strlut_mutex);
  hash_t name_hash = getStrHash(strlut, name.c_str());
  pthread_mutex_unlock(strlut_mutex);

  // Bad files...
  if (name_hash == HASH_null || inode == -1)
  {
#ifdef DEBUG
    fprintf( stderr, "DEBUG %s:%d Bad file. name=\"%s\" inode=%d\n",
        __FILE__, __LINE__, name.c_str(), inode );
#endif

    // It is an error only if it is the first item, i.e. item=0.
    if (item == 0) return false;
    else           return true;
  }

  // Checks if a list for the name hash already exists, if not create
  list< FileInstance* >* lfi;
  unordered_map< hash_t, list< FileInstance* >* >::iterator fiitr
    = evt.file_instances.find(name_hash);
  if (fiitr != evt.file_instances.end())
  { lfi = fiitr->second; }
  else
  {
    lfi = new list<FileInstance *>();
    evt.file_instances[name_hash] = lfi;
  }

  // Insert the file instance
  lfi->push_back(new FileInstance(name_hash, inode, mode, ouid, ogid));

  return true;
}

//-------------------------------------------------------------------

typedef struct
{
  bool            done;
  strlut_t        *strlut;
  const SCNUM     *scnum;
  ProgFile        *rootprog;
  list<string*>   *ignore_paths;
  list<PEVENT>    work; /* events to be worked on */
  list<PEVENT>*   good; /* good events to be assembled */
  pthread_mutex_t strlut_mutex;
  pthread_mutex_t rootprog_mutex;
  pthread_mutex_t good_mutex;
  pthread_mutex_t mutex;
  pthread_cond_t  cond;
} GEVT_CTX;

typedef struct
{
  EVENT         *evt;
  GEVT_CTX      *gevt_ctx;
} GEVT_CALLBACK_CTX;

/*!
 * getEvent callback, used by auparse_add_callback. This callback function is
 * the starting point for parsing the records.
 * */
void geCallback(auparse_state_t *au,
    auparse_cb_event_t cb_event_type,
    void *ptr)
{
  if (cb_event_type != AUPARSE_CB_EVENT_READY) return;

  GEVT_CALLBACK_CTX *ctx  = (GEVT_CALLBACK_CTX*) ptr;
  GEVT_CTX *gevt_ctx      = ctx->gevt_ctx;
  EVENT *evt              = ctx->evt;
  //fprintf(stderr, "DEBUG [EVT %08x] callback\n", evt);

  int res = auparse_first_record(au);
  while (res == 1 && evt->bad == false)
  {
    //fprintf(stderr, "DEBUG [CBS %d] %s\n", evt->serial, auparse_get_record_text(au));

    // need to get the type again, since it can change.
    switch (auparse_get_type(au))
    {
      case AUDIT_SYSCALL:
        if (syscallHandler(*(gevt_ctx->strlut),
              &(gevt_ctx->strlut_mutex),
              au,
              *(gevt_ctx->scnum),
              *evt,
              *(gevt_ctx->rootprog),
              &(gevt_ctx->rootprog_mutex)) == false)
        { evt->bad = true; }
        break;
      case AUDIT_CWD:
        cwdHandler(au, *evt);
        break;
      case AUDIT_PATH:
        if (pathHandler(*(gevt_ctx->strlut),
              &(gevt_ctx->strlut_mutex),
              au,
              *evt,
              *(gevt_ctx->ignore_paths)) == false)
        { /*fprintf(stderr, "DEBUG %s:%d [%d] Bad path.\n", __FILE__, __LINE__, evt->serial);*/ evt->bad = true; }
        break;
      case AUDIT_EXECVE:
        execveHandler(au, gevt_ctx->scnum->__NR_execve, *evt);
        break;
    }

    res = auparse_next_record(au);
  }
}



/*!
 * getEvent consumer thread.
 * */
void *geConsumer(void *ptr)
{
  list< pair<int, char*> >::iterator b, e;

  GEVT_CTX *c = (GEVT_CTX*) ptr;

  while (true)
  {
    // wait for work...
    pthread_mutex_lock(&(c->mutex));
    while (c->work.empty() && c->done == false)
    { pthread_cond_wait(&(c->cond), &(c->mutex)); }
    if (c->work.empty() && c->done == true)
    {
      pthread_mutex_unlock(&(c->mutex));
      break;
    }
    PEVENT w = c->work.front();
    c->work.pop_front();
    pthread_mutex_unlock(&(c->mutex));

    //
    // do work
    //

    GEVT_CALLBACK_CTX gevt_cb_ctx;
    gevt_cb_ctx.evt = w;
    gevt_cb_ctx.gevt_ctx = c;
    if (w->bad == false)
    {
      auparse_state_t *au = auparse_init(AUSOURCE_FEED, NULL);
      auparse_add_callback(au, geCallback, (void*) &gevt_cb_ctx, NULL);
      for (b = w->records.begin(), e = w->records.end();
          b != e && w->bad == false; b++)
      { auparse_feed(au, b->second, strlen(b->second)); }
      int rc = auparse_flush_feed(au);
      assert(rc == 0);
      auparse_destroy(au);
    }
    else
    {
      fprintf(stderr, "DEBUG: Can there ever be a bad work even before we begin?\n");
    }

    // Free record texts
    for (b = w->records.begin(), e = w->records.end();
        b != e; b++) { delete [] b->second; }

    if (w->bad == false)
    {
      pthread_mutex_lock(&(c->good_mutex));
      c->good->push_back(w);
      pthread_mutex_unlock(&(c->good_mutex));
    }
    else {
      // free bad work
      if (w->syscall != NULL) delete w->syscall;
      pair<long, list<FileInstance*>* > p;
      BOOST_FOREACH(p, w->file_instances)
      {
        BOOST_FOREACH(FileInstance *fi, *p.second)
        { if (fi->getNumSyscalls() == 0) delete fi; }
        delete p.second;
      }
      delete w;
    }
  }
  pthread_exit(NULL);
}


/*
 * Add the partial event p to parts.
 * */
static void geAddPart(
    unordered_map<serial_t, list<PEVENT>* > &parts,
    PEVENT p )
{
  list<PEVENT>* l;
  unordered_map<serial_t, list<PEVENT>* >::iterator pitr
    = parts.find( p->serial );
  if (pitr != parts.end())
  {
    l = pitr->second;
  }
  else
  {
    l = new list<PEVENT>();
    parts[p->serial] = l;
  }

  l->push_back( p );
}

/*
 * Gets a part that matches the timestamp ts.
 *
 * The part is removed from parts if it exists.
 * Otherwise, a new part is allocated, but not
 * put into parts. The assumption is that most
 * events should be complete, and thus there
 * isn't a need to save incomplete parts.
 *
 * The found or new part is returned.
 * */
PEVENT geGetPart(
    unordered_map<serial_t, list<PEVENT>* > &parts,
    const au_event_t* ts )
{
  PEVENT p = NULL;

  // Look for the event list mapped to the serial.
  // Create one if serial not found.
  unordered_map<serial_t, list<PEVENT>* >::iterator pitr
    = parts.find( ts->serial );
  if (pitr != parts.end())
  {
    list<PEVENT>* l = pitr->second;

    // Look for the evt that matches.
    // Create one if none exists.
    list<PEVENT>::iterator litr;
    for (litr = l->begin(); litr != l->end(); ++litr)
    {
      PEVENT e = *litr;
      if (e->serial == ts->serial &&
          e->sec == ts->sec &&
          e->milli == ts->milli)
      {
        p = e;
        break;
      }
    }

    if (p != NULL)
      l->erase( litr );
  }

  if (p == NULL)
  { // create new event
    p               = new EVENT();
    p->bad          = false;
    p->serial       = ts->serial;
    p->sec          = ts->sec;
    p->milli        = ts->milli;
    p->process      = NULL;
    p->syscall      = NULL;
    p->items        = -1;
  }

  return p;
}

/*
 * Returns true if the event is complete.
 * */
bool geIsComplete( PEVENT e )
{
  if (e->items == -1) return false;

  int ns = 0; // number of syscall records
  int ne = 0; // number of execve records
  int nc = 0; // number of cwd records
  int np = 0; // number of path records

  pair<int, char*> p;
  BOOST_FOREACH( p, e->records )
  {
    switch(p.first)
    {
      case AUDIT_SYSCALL: ns++; break;
      case AUDIT_EXECVE:  ne++; break;
      case AUDIT_CWD:     nc++; break;
      case AUDIT_PATH:    np++; break;
    }
  }

  //fprintf(stderr, "ns %d nc %d np %d items %d\n",
  //    ns, nc, np, e->items);
  // We're a little lazy and didn't check ne.
  // Let's assume it is there, otherwise we need to parse
  // the syscall record for the syscall number.
  return (ns == 1 && nc == 1 && np == e->items);
}

static void geFreeParts( unordered_map<serial_t, list<PEVENT>* > &parts )
{
  unordered_map<serial_t, list<PEVENT>* >::iterator b, e;
  for (b = parts.begin(), e = parts.end(); b != e; ++b)
  {
    list<PEVENT>* l = b->second;
    list<PEVENT>::iterator x, y;
    for (x = l->begin(), y = l->end(); x != y; ++x)
    {
      PEVENT p = *x;
      list< pair<int, char*> >::iterator q, r;
      for (q = p->records.begin(), r = p->records.end(); q != r; ++q)
        delete q->second;
      if (p->syscall != NULL) delete p->syscall; 
      delete p;
    }
    delete l;
  }
}

/*
 * Returns value of items field for SYSCALL record.
 * */
int geGetItems( const char* s )
{
  const char* f = "items=";
  return *(strstr(s, f) + strlen(f)) - '0';
}

/*!
 * Get info from each record.
 * */
int getEvent(
    const int nprocs,
    strlut_t &strlut,
    auparse_state_t *au,
    const SCNUM &scnum,
    ProgFile &rootprog,
    File &rootfile,
    list<string *> &ignore_paths,
    list<PEVENT> &events)
{
  unordered_map<serial_t, list<PEVENT>* > parts;

  // Add rules
  if (ausearch_add_item(au, "syscall", "=", "2", AUSEARCH_RULE_CLEAR) != 0)
  { fprintf(stderr, "Error adding rule.\n"); return -1; }
  if (ausearch_add_item(au, "syscall", "=", "59", AUSEARCH_RULE_OR) != 0)
  { fprintf(stderr, "Error adding rule.\n"); return -1; }
  if (ausearch_add_item(au, "type", "=", "EXECVE", AUSEARCH_RULE_OR) != 0)
  { fprintf(stderr, "Error adding rule.\n"); return -1; }
  if (ausearch_add_item(au, "type", "=", "CWD", AUSEARCH_RULE_OR) != 0)
  { fprintf(stderr, "Error adding rule.\n"); return -1; }
  if (ausearch_add_item(au, "type", "=", "PATH", AUSEARCH_RULE_OR) != 0)
  { fprintf(stderr, "Error adding rule.\n"); return -1; }

  // Without this, the number of threads that can be created is limited.
  //pthread_attr_t id_attr;
  //pthread_attr_init (&id_attr);
  //pthread_attr_setdetachstate(&id_attr, PTHREAD_CREATE_DETACHED);

  //
  // Spawn geConsumer
  //
  GEVT_CTX ctx;
  ctx.done             = false;
  ctx.strlut           = &strlut;
  ctx.scnum            = &scnum;
  ctx.rootprog         = &rootprog;
  ctx.ignore_paths     = &ignore_paths;
  ctx.good             = &events;
  ctx.strlut_mutex     = PTHREAD_MUTEX_INITIALIZER;
  ctx.rootprog_mutex   = PTHREAD_MUTEX_INITIALIZER;
  ctx.good_mutex       = PTHREAD_MUTEX_INITIALIZER;
  ctx.mutex            = PTHREAD_MUTEX_INITIALIZER;
  ctx.cond             = PTHREAD_COND_INITIALIZER;

  pthread_t getevt_threads[nprocs];
  for (int i = 0; i < nprocs; ++i)
  {
    int rc = pthread_create(&getevt_threads[i], NULL, geConsumer, (void*)&ctx);
    assert(rc == 0);
  }

  while (ausearch_next_event(au) > 0)
  {
    // Retrieve EVENT using event serial. If EVENT does not exist,
    // create a new one and insert into the set.

    const au_event_t *ts = auparse_get_timestamp(au);
    if (ts != NULL) {
      //fprintf( stderr, "DEBUG serial %d\n", ts->serial );

      PEVENT p = geGetPart( parts, ts );

      // Copy records
      int rc = auparse_first_record(au);
      while (rc == 1)
      {
        const char* r = auparse_get_record_text(au);
        //fprintf(stderr, "DEBUG %s %d: \"%s\"\n", __FILE__, __LINE__, r);
        size_t n = strlen(r) + 2;
        char* s = new char[n];
        strncpy(s, r, n);
        strcat(s, "\n");

        // Get number of items
        int ty = auparse_get_type(au);
        if (ty == AUDIT_SYSCALL) {
          p->items = geGetItems(r);
        }

        p->records.push_back( make_pair( ty, s ) );
        rc = auparse_next_record(au);
      }

      // Check if evt is complete
      if (geIsComplete( p ) == true )
      {
        // Put work into list
        pthread_mutex_lock(&(ctx.mutex));
        ctx.work.push_back( p ); // queue work
        pthread_cond_signal(&(ctx.cond));
        pthread_mutex_unlock(&(ctx.mutex));
      }
      else
      {
        //fprintf( stderr, "DEBUG Incomplete. Add as part.\n" );
        geAddPart( parts, p );
      }
    }

    auparse_next_event(au);
  }
  pthread_mutex_lock(&(ctx.mutex));
  ctx.done = true;
  pthread_cond_broadcast(&(ctx.cond));
  pthread_mutex_unlock(&(ctx.mutex));

  for (int i = 0; i < nprocs; ++i)
  {
    int rc = pthread_join(getevt_threads[i], NULL);
    assert(rc == 0);
  }

  // Free incomplete parts
  geFreeParts( parts );

  assert(ctx.work.empty());

  //pthread_attr_destroy(&id_attr); 
  pthread_mutex_destroy(&(ctx.strlut_mutex));
  pthread_mutex_destroy(&(ctx.rootprog_mutex));
  pthread_mutex_destroy(&(ctx.mutex));
  pthread_cond_destroy(&(ctx.cond));

  return 0;
}

