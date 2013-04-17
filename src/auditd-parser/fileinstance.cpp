#include <sqlite3.h>
#include <grp.h>
#include <stdio.h>
#include <math.h>
#include <assert.h>
#include <boost/foreach.hpp>
#include <boost/filesystem.hpp>
#include <string>
#include <unordered_map>
#include <map>
#include <algorithm>
#include "fileinstance.h"
#include "syscall.h"
#include "process.h"
#include "program.h"
#include "utilities.h"

#include "db.h"

using namespace std;
using namespace boost::filesystem;

/*!
 * FileInstance constructor.
 * */
FileInstance::FileInstance(
    const hash_t name_hash,
    const inode_t inode,
    const mode_t mode,
    const uid_t ouid,
    const gid_t ogid)
{
  instance_of_  = NULL;
  name_hash_    = name_hash;
  inode_        = inode;
  sc_mode_         = mode;
  sc_uid_         = ouid;
  sc_gid_         = ogid;
  last_syscall_ = NULL;
}

/*
 * Destructor
 * */
FileInstance::~FileInstance()
{}

//------------------------------------------------------

/*!
 * Add syscall on instance.
 * */
void FileInstance::addSyscall(serial_t serial, Syscall *sc)
{
  unordered_map<serial_t, Syscall *>::iterator it
    = syscalls_.find(serial);
  if (it != syscalls_.end()) return; //exists
  syscalls_[serial] = sc;
}

//------------------------------------------------------

void FileInstance::setMode(const mode_t mode) { sc_mode_ = mode; }
void FileInstance::setOuid(const uid_t ouid)  { sc_uid_ = ouid; }
void FileInstance::setOgid(const gid_t ogid)  { sc_gid_ = ogid; }
void FileInstance::setInstanceOf(File *instance_of)
{ instance_of_ = instance_of; }

long    FileInstance::getNameHash()   { return name_hash_; }
inode_t FileInstance::getInode()      { return inode_; }
mode_t  FileInstance::getMode()       { return sc_mode_; }
uid_t   FileInstance::getOuid()       { return sc_uid_; }
gid_t   FileInstance::getOgid()       { return sc_gid_; }
File *  FileInstance::getInstanceOf() { return instance_of_; }
size_t  FileInstance::getNumSyscalls() { return syscalls_.size(); }

struct getSyscall
{
  set<Syscall *> *syscalls_;
  getSyscall(set<Syscall *> *syscalls) : syscalls_(syscalls) {}
  void operator() (pair<serial_t, Syscall *> p) { syscalls_->insert(p.second); }
  void setCaller(FileInstance *fi) {}
};

void    FileInstance::getSyscalls(set<Syscall *> &syscalls)
{ for_each_syscall(getSyscall(&syscalls)); }

bool FileInstance::isVoid() { return (syscalls_.size() == 0); }

//------------------------------------------------------

struct getLastSyscall_
{
  Syscall **lastSyscall_;
  getLastSyscall_(Syscall **lastSyscall) : lastSyscall_(lastSyscall) {}
  void operator()(pair<serial_t, Syscall*> p)
  {
    if (*lastSyscall_ == NULL || p.first > (*lastSyscall_)->getSerial())
      *lastSyscall_ = p.second;
  }
};

/*!
 * Returns the serial of the last syscall on
 * this file instance.
 * */
serial_t FileInstance::getLastSyscallSerial()
{
  if (last_syscall_ != NULL) return last_syscall_->getSerial();
  for_each(syscalls_.begin(), syscalls_.end(), getLastSyscall_(&last_syscall_));
  return last_syscall_->getSerial();
}

//------------------------------------------------------

/*!
 * Prints file instance inode, mode, uid, and gid.
 * */
void FileInstance::pp(FILE *out)
{
  fprintf(out, "\t\t%d,%04o,%d,%d\n", inode_, sc_mode_, sc_uid_, sc_gid_);
}

//------------------------------------------------------

/*!
 * Purge ALL SCOnFile syscalls.
 * */
void FileInstance::purgeSCOnFile()
{
  unordered_map<serial_t, Syscall *> saved_syscalls;

  pair<serial_t, Syscall *> p;
  BOOST_FOREACH(p, syscalls_)
  {
    Syscall *sc = p.second;
    SCOnFile *scof = dynamic_cast<SCOnFile *>(sc);
    if (scof)
    {
      // fprintf(stderr, "DEBUG: FileInstance purge syscall %08x [serial %d]\n",
      //    scof, scof->getSerial());
      scof->reversePurgeProc();
    }
    else
    {
      saved_syscalls.insert(pair<serial_t, Syscall *>(sc->getSerial(), sc));
    }
  }

  syscalls_.clear();
  syscalls_ = saved_syscalls;
}

//------------------------------------------------------

bool FileInstance::operator==(const FileInstance &rhs) const
{
  return (this->name_hash_ == rhs.name_hash_ &&
      this->inode_ == rhs.inode_ &&
      this->sc_mode_ == rhs.sc_mode_ &&
      this->sc_uid_ == rhs.sc_uid_ &&
      this->sc_gid_ == rhs.sc_gid_); 
}

bool FileInstance::operator!=(const FileInstance &rhs) const
{
  return !(*this == rhs);
}

FileInstance& FileInstance::operator+=(const FileInstance &rhs)
{
  // Combine syscalls
  pair<serial_t, Syscall*> p;
  BOOST_FOREACH(p, rhs.syscalls_)
  {
    this->syscalls_[p.first] = p.second;
  }

  return *this;
}

void FileInstance::dumpDB( sqlite3* conn,
    strlut_t& strlut,
    sqlite3_int64 rid )
{
  pair< serial_t, Syscall*> p;
  BOOST_FOREACH( p, syscalls_ )
  { p.second->dumpDB( conn, rid, sc_uid_, sc_gid_, sc_mode_, strlut ); }
}

void FileInstance::dumpDot( FILE *out, strlut_t& strlut )
{
  pair< serial_t, Syscall*> p;
  BOOST_FOREACH( p, syscalls_ )
  { p.second->dumpDot( out, sc_uid_, sc_gid_, sc_mode_, strlut ); }
}
