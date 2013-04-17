#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <boost/foreach.hpp>
#include <boost/tokenizer.hpp>
#include <set>
#include <list>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include "process.h"
#include "syscall.h"
#include "file.h"
#include "program.h"
#include "strhash.h"

#include "db.h"

using namespace std;

//==========
// FUNCTORS
//==========

/*!
 * Returns true if process has specified pid.
 * */
struct cmpProc
{
  pid_t pid_;
  cmpProc(pid_t pid) : pid_(pid) {}
  bool operator()(Process *proc) const { return (pid_ == proc->getPid()); }
};


//===================================================================
// Process Class
//===================================================================

/*!
 * Process Constructor.
 * */
Process::Process(Program *instance_of, const pid_t pid)
{
  instance_of_  = instance_of;
  pid_          = pid;
  dotdone_      = false;
}

pid_t Process::getPid()             { return pid_; }
size_t Process::getNumSyscalls()  { return syscalls_.size(); }
Program *Process::getInstanceOf() { return instance_of_; }

/*!
 * Pretty prints process pid.
 * */
void Process::pp(FILE *out)
{
  unordered_map<pid_t, Process *>::iterator b, e;
  fprintf(out, "\t%d", pid_);

  // Print parent
  if (!parents_.empty())
  {
    fprintf(out, "\n\t\t(");
    for (b = parents_.begin(), e = parents_.end(); b != e; ++b)
    {
      if (b != parents_.begin()) fprintf(out, ",");
      fprintf(out, "%d", b->second->getPid());
    }
    fprintf(out, ")");
  }

  // Print children
  if (!children_.empty())
  {
    fprintf(out, "\n\t\t[");
    for (b = children_.begin(), e = children_.end(); b != e; ++b)
    {
      if (b != children_.begin()) fprintf(out, ", ");
      fprintf(out, "%d", b->second->getPid());
    }
    fprintf(out, "]");
  }
  fprintf(out, "\n");
}

/*!
 * Adds parent process if none with its Pid exists.
 *
 * Why do some processes have more than 1 parent??!!
 * Maybe because of init, which adopts zombies
 * */
void Process::addParent(Process *parent)
{
  pid_t parent_pid = parent->getPid();
  if (parents_.find(parent_pid) == parents_.end())
    parents_[parent_pid] = parent;
}

/*!
 * Adds child process if none with its Pid exists.
 * */
void Process::addChild(Process *child)
{
  pid_t child_pid = child->getPid();
  if (children_.find(child_pid) == children_.end())
    children_[child_pid] = child;
}

/*!
 * Adds syscall if it doesn't already exist.
 * */
void Process::addSyscall(const serial_t serial, Syscall *sc)
{
  unordered_map<serial_t, Syscall *>::iterator it
    = syscalls_.find(serial);
  //  = find_if(syscalls_.begin(), syscalls_.end(), cmpSyscall(sc));
  if (it != syscalls_.end()) return;
  //syscalls_.push_back(sc);
  syscalls_[serial] = sc;
}

void Process::ppFile(FILE *out, strlut_t &strlut)
{
  unordered_map<serial_t, Syscall *>::iterator b, e;
  for (b = syscalls_.begin(), e = syscalls_.end();
      b != e; ++b)
  {
    SCOnFile *scof = dynamic_cast<SCOnFile*>(b->second);
    if (scof == NULL) continue;

    scof->ppFile(out, strlut);
  }
}

/*!
 * Purges syscalls in list.
 * */
void Process::purgeSyscalls(set<Syscall *> &bad)
{
  // For each syscall to be purged...
  BOOST_FOREACH(Syscall *sc, bad)
  { purgeSyscall(sc); }
}

void Process::purgeSyscall(Syscall *bad)
{
  unordered_map<serial_t, Syscall *>::iterator it
    = syscalls_.find(bad->getSerial());

  // Erases the syscall if we have it
  if (it != syscalls_.end())
  {
//#ifdef DEBUG
//    fprintf(stderr, "DEBUG: Process      purge syscall %08x [serial %d]\n",
//        bad, bad->getSerial());
//#endif
    syscalls_.erase(it);
  }
}

/*
 * Dumps process's program information to database. If it has parents, they are
 * called recursively to dump their information.
 * */
sqlite3_int64 Process::dumpDB( sqlite3* conn, strlut_t& strlut )
{
  sqlite3_int64 progid = instance_of_->dumpDB( conn, strlut );
  sqlite3_int64 procid = -1;

  //fprintf( stderr, "DEBUG Process::dumpDB [%d] progid=%d parents_.size()=%zu\n",
  //    pid_, progid, parents_.size() );
  if (parents_.size() == 0)
  { // If there are no parents, set ppid to -1.
    procid = insertProcess( conn, progid, pid_, (sqlite3_int64) -1);
  }
  else
  {
    pair<pid_t, Process*> p;
    BOOST_FOREACH( p, parents_ )
    {
      //fprintf(stderr, "DEBUG Process::dumpDB [%d] dumping ppid %d\n", pid_, p.first);
      procid = insertProcess( conn, progid, pid_, p.first);
      //fprintf(stderr, "DEBUG Process::dumpDB [%d] Got procid %d\n", pid_, procid);
    }
    //if (parents_.size() != 1)
    //  fprintf( stderr, "WARNING: [%d] Has %zu parents!\n",
    //      pid_, parents_.size() );
  }
  //fprintf(stderr, "DEBUG Process::dumpDB [%d] Returning procid %d\n", pid_, procid);
  return procid;
}

void Process::dumpDot( FILE *out, strlut_t &strlut )
{
  pair<pid_t, Process*> p;

  if (dotdone_ == true) return;

  const char *unknown = "UNKNOWN";
  const char *comm = strlut[instance_of_->getCommHash()];
  if (comm[0] == '\0') comm = unknown;

  instance_of_->dumpDotDecl( out, strlut );

  // Print edges
  BOOST_FOREACH( p, children_ )
  {
    Process *childproc = p.second;
    Program *childprog = childproc->getInstanceOf();

    childprog->dumpDotDecl( out, strlut );
    const char *childcomm = strlut[childprog->getCommHash()];
    if (childcomm[0] == '\0') childcomm = unknown;

    fprintf(out, "\t%lu -> %lu\n",
        instance_of_->getCommHash(),
        childprog->getCommHash() );
  }

  dotdone_ = true;

  BOOST_FOREACH( p, parents_ )
  {
    Process *parentproc = p.second;
    parentproc->dumpDot( out, strlut );
  }

  BOOST_FOREACH( p, children_ )
  {
    Process *childproc = p.second;
    childproc->dumpDot( out, strlut );
  }
}
