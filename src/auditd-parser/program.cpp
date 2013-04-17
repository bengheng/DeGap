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

#include <sqlite3.h>
#include "db.h"

using namespace std;

/*!
 * Program Constructors.
 * */
Program::Program(const hash_t comm_hash, const hash_t exe_hash)
{
  comm_hash_ = comm_hash;
  exe_hash_  = exe_hash;
  dotdecl_ = false;
}

/*!
 * Delete process.
 * */
struct delProc {
  delProc() {}
  void operator() (pair<int, Process *> entry) const
  {
    Process *proc = entry.second;
    delete proc;
  }
};

/*!
 * Prints process.
 * */
struct ppProc {
  FILE *out_;
  ppProc(FILE *out) : out_(out) {}
  void operator() (pair<int, Process *> entry) const
  {
    Process *proc = entry.second;
    proc->pp(out_);
  }
};

/*!
 * Program Destructor.
 * */
Program::~Program()
{
  // Frees processes
  for_each(procs_.begin(), procs_.end(), delProc());
}

hash_t       Program::getCommHash() { return comm_hash_;    }
hash_t       Program::getExeHash()  { return exe_hash_;     }
size_t       Program::getNumProcs() { return procs_.size(); }
/*!
 * Returns pointer to process with Pid. If none found,
 * return NULL.
 * */
Process * Program::getProcess(const pid_t pid)
{
  // If this program has a process with pid, return it.
  unordered_map<int, Process *>::iterator it
    = procs_.find(pid);
  if (it != procs_.end()) return it->second;

  // Didn't find any process with pid.
  return NULL;
}

struct getRootAccessedFiles
{
  std::set<File *> *shortlist_;
  getRootAccessedFiles(std::set<File *> *shortlist) : shortlist_(shortlist) {}
  void operator() (std::pair<serial_t, Syscall *> p)
  {
    SCOnFile *scof;
    if ((scof = dynamic_cast<SCOpen*>(p.second)) == NULL
        || scof->getEuid() != 0) return;

    BOOST_FOREACH(FileInstance *fi, scof->getFileInstances())
    { shortlist_->insert(fi->getInstanceOf()); }
  }
};

struct shortlistProc
{
  set<File *> *shortlist_;
  shortlistProc(set<File *> *shortlist) : shortlist_(shortlist) {}
  void operator() (pair<int, Process *> p)
  {
    Process *proc = p.second;
    proc->forEachSyscall(getRootAccessedFiles(shortlist_));
  }
};

/*!
 * Get files from syscalls with euid 0.
 * */
void Program::getShortlist(set<File *> &shortlist)
{
  // If this program has a process with pid, return it.
  forEachProcess( shortlistProc(&shortlist) );
}

/*!
 * Adds all processes to set.
 * */
void Program::getAllProcesses(set<Process *> &procs)
{
  // For every process, insert the process
  // and its parents and children.
  unordered_map<int, Process *>::iterator b, e;
  for (b = procs_.begin(), e = procs_.end();
      b != e; ++b)
  {
    Process *proc = b->second;
    unordered_map<pid_t, Process *> &parents = proc->getParents();
    unordered_map<pid_t, Process *> &children = proc->getChildren();
    unordered_map<pid_t, Process *>::iterator lb, le;

    procs.insert(proc);

    for (lb = parents.begin(), le = parents.end(); lb != le; ++lb)
      procs.insert(lb->second);
    for (lb = children.begin(), le = children.end(); lb != le; ++lb)
      procs.insert(lb->second);

  }
}

/*!
 * Make an instance of the program, i.e. process. If there is already
 * an existing process with the same Pid, skip.
 *
 * Warning: This function assumes that you've already checked for
 * matching comm and exe. It just checks existing processes based on Pid,
 * nothing else!
 * */
Process * Program::mkProcess(const pid_t pid)
{
  Process *proc = NULL;

  // Checks that there are no existing instances with same Pid.
  // (Why not? The probability is small, but it may be possible...)
  unordered_map<pid_t, Process *>::iterator it = procs_.find(pid);
  if (it != procs_.end()) return it->second;

  proc = new Process(this, pid);
  procs_[pid] = proc;
  return proc;
}

/*!
 * Pretty-print program info, including process pids.
 * */
void Program::pp(FILE *out, strlut_t& strlut)
{
  fprintf(out, "comm = %s exe = %s\n",
      strlut[comm_hash_],
      strlut[exe_hash_]);
  for_each(procs_.begin(), procs_.end(), ppProc(out));
}

void Program::ppFile(FILE *out, strlut_t& strlut)
{
  pair<int, Process *> p;
  BOOST_FOREACH(p, procs_)
  { p.second->ppFile(out, strlut); }
}

/*!
 * Purges the syscalls if they are found in the processes.
 * */
void Program::purgeSyscalls(set<Syscall *> &bad)
{
  unordered_map<int, Process *> saved;

  pair<int, Process *> p;
  BOOST_FOREACH(p, procs_)
  {
    pid_t pid = p.first;
    Process *proc = p.second;
    proc->purgeSyscalls(bad);

    // Delete procs without syscalls
    if (proc->getNumSyscalls() == 0) delete proc;
    else saved.insert(pair<int, Process *>(pid, proc));
  }

  // Restore the saved procs 
  procs_.clear();
  procs_ = saved;
}

sqlite3_int64 Program::dumpDB( sqlite3 *conn, strlut_t &strlut )
{
  return insertProgram( conn, strlut[comm_hash_], strlut[exe_hash_] );
}

void Program::dumpDot( FILE *out, strlut_t &strlut )
{
  pair<int, Process *> p;
  BOOST_FOREACH(p, procs_)
  {
    p.second->dumpDot(out, strlut);
  }
}

void Program::dumpDotDecl( FILE *out, strlut_t &strlut )
{
  if ( dotdecl_ == false ) {
    const char *unknown = "UNKNOWN";
    const char *comm = strlut[comm_hash_];
    const char *exe = strlut[exe_hash_];

    if (comm[0] == '\0') comm = unknown;
    if (exe[0] == '\0') exe = unknown;

    fprintf(out, "\t%lu [shape=\"ellipse\" label=\"%s\\n%s\"]\n",
        comm_hash_, comm, exe);
    dotdecl_ = true;
  }
}

