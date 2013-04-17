#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <boost/foreach.hpp>
#include <set>
#include <list>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include "process.h"
#include "syscall.h"
#include "file.h"
#include "progfile.h"
#include "strhash.h"

using namespace std;

/*!
 * ProgFile Constructor.
 */
ProgFile::ProgFile(const hash_t name_hash)
{
  name_hash_ = name_hash;
}

/*!
 * ProgFile Destructor.
 * */
ProgFile::~ProgFile()
{
  // Delete children program files
  BOOST_FOREACH(ProgFile *pf, children_) { delete pf; }

  // Delete own programs
  BOOST_FOREACH(Program *p, programs_) { delete p; }
}

/*!
 * Adds child program.
 * */
Program *ProgFile::addProgram(
    list< hash_t >::iterator hashlist_end,
    list< hash_t >::iterator hashlist_itr,
    const hash_t comm_hash,
    const hash_t exe_hash)
{
  return addProgram(hashlist_end, hashlist_itr,
      NULL, comm_hash, exe_hash);
}


/*!
 * Private function for adding child program.
 * */
Program *ProgFile::addProgram(
    list< hash_t >::iterator hashlist_end,
    list< hash_t >::iterator hashlist_itr,
    ProgFile *top,
    const hash_t comm_hash,
    const hash_t exe_hash)
{
  if (hashlist_itr == hashlist_end)
  {
    top_ = top;

    // Check if there's a program with the same comm.
    BOOST_FOREACH(Program *p, programs_)
    { if (p->getCommHash() == comm_hash) return p; }

    // Didn't find any program with same comm,
    // create new program. 
    Program *p = new Program(comm_hash, exe_hash);
    programs_.push_back(p);
    return p; 
  }

  ProgFile *child = NULL;
  BOOST_FOREACH(ProgFile *pf, children_)
  {
    if (pf->getNameHash() == *hashlist_itr)
    { child = pf; break; }
  }

  // Can't find child whose name is same as current token
  if (child == NULL)
  {
    child = new ProgFile(*hashlist_itr);
    children_.push_back(child);
  }

  if (top == NULL) top = child;

  return child->addProgram(hashlist_end, ++hashlist_itr,
      top, comm_hash, exe_hash);
}



/*!
 * Get files from syscalls with euid 0.
 * */
void ProgFile::getShortlist(set<File *> &shortlist)
{
  // If this program has a process with pid, return it.
  BOOST_FOREACH(Program *p, programs_)
  { p->getShortlist(shortlist); }

  // Get shortlist from children.
  BOOST_FOREACH(ProgFile *pf, children_)
  { pf->getShortlist(shortlist); }
}

/*!
 * Get process with pid.
 * */
Process * ProgFile::getProcess(const pid_t pid)
{
  // If there is a program with process having pid, return it.
  BOOST_FOREACH(Program *p, programs_)
  {
    Process * proc = p->getProcess(pid);
    if (proc != NULL) return proc;
  }

  // We don't have a program with that pid. Try the children.
  BOOST_FOREACH(ProgFile *pf, children_)
  {
    Process *proc = pf->getProcess(pid);
    if (proc != NULL) return proc;
  }

  return NULL; // still nothing
}

hash_t ProgFile::getNameHash() { return name_hash_; }

/*!
 * Purge syscalls in list.
 * */
void ProgFile::purgeSyscalls(set<Syscall *> &bad)
{
  list<Program *> saved;

  BOOST_FOREACH(Program *prog, programs_)
  {
    prog->purgeSyscalls(bad);

    // Delete progs without procs
    if (prog->getNumProcs() == 0) delete prog;
    else saved.push_back(prog);
  }

  // Restore the saved progs 
  programs_.clear();
  programs_ = saved;

  BOOST_FOREACH(ProgFile *child, children_)
  { child->purgeSyscalls(bad); }
}

void ProgFile::dumpDot( FILE *out, strlut_t &strlut )
{
  // Dump Dot for this ProgFile
  BOOST_FOREACH(Program *p, programs_)
  { p->dumpDot(out, strlut); }

  // Dump Dot for children.
  BOOST_FOREACH(ProgFile *pf, children_)
  { pf->dumpDot(out, strlut); }
}
