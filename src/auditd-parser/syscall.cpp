#include <fcntl.h>
#include <assert.h>
#include <boost/foreach.hpp>
#include <typeinfo>
#include <list>
#include <vector>
#include <string>
#include <algorithm>
#include "process.h"
#include "program.h"
#include "file.h"
#include "syscall.h"
#include "strhash.h"

#include "db.h"

using namespace std;

Syscall::Syscall(int scnum, time_t sec, unsigned int milli, unsigned long serial)
{
  sec_      = sec;
  milli_    = milli;
  serial_   = serial;
  syscall_  = scnum;
  auid_     = -1;
  uid_      = -1;
  gid_      = -1;
  euid_     = -1;
  suid_     = -1;
  fsuid_    = -1;
  egid_     = -1;
  sgid_     = -1;
  fsgid_    = -1;
  proc_     = NULL;
}

void Syscall::setSuccess(const char *success)
{ success_ = ( strncmp(success, "yes", 4) == 0 ? true : false ); }
void Syscall::setExit(int exit)               { exit_ = exit; }
void Syscall::setAuid(int auid)               { auid_ = auid; }
void Syscall::setUid(uid_t uid)                 { uid_ = uid; }
void Syscall::setGid(gid_t gid)                 { gid_ = gid; }
void Syscall::setEuid(uid_t euid)               { euid_ = euid; }
void Syscall::setSuid(uid_t suid)               { suid_ = suid; }
void Syscall::setFsuid(uid_t fsuid)             { fsuid_ = fsuid; }
void Syscall::setEgid(gid_t egid)               { egid_ = egid; }
void Syscall::setSgid(gid_t sgid)               { sgid_ = sgid; }
void Syscall::setFsgid(gid_t fsgid)             { fsgid_ = fsgid; }
void Syscall::setProcess(Process *proc)
{
  assert(proc_ == NULL);
  proc_ = proc;
}

bool Syscall::getSuccess()          { return success_; }
unsigned long Syscall::getSerial()  { return serial_; }
Process *Syscall::getProcess()      { return proc_; }

void Syscall::pp(FILE *out, strlut_t& strlut)
{
  assert(proc_ != NULL);
  fprintf(out, "syscall=%d proc=%s\n",
      syscall_, strlut[proc_->getInstanceOf()->getCommHash()]);

  /*
     fprintf(out, "syscall=%d proc=%s files=",
     syscall_, proc_->getInstanceOf()->getComm());
     list<FileInstance *>::iterator b, e;
     for(b = fileinstances_.begin(), e = fileinstances_.end(); b != e; ++b)
     {
     if (b != fileinstances_.begin())
     fprintf(out, ", ");
     fprintf(out, "%s", (*b)->getName().c_str());
     }
     fprintf(out, "\n");
     */
}

bool Syscall::operator==(Syscall &other) const
{
  assert( typeid(*this) == typeid(other));
  return (
      (sec_     == other.sec_    ) &&
      (milli_   == other.milli_  ) &&
      (serial_  == other.serial_ ) &&
      (syscall_ == other.syscall_) &&
      (success_ == other.success_) &&
      (exit_    == other.exit_   ) &&
      (auid_    == other.auid_   ) &&
      (uid_     == other.uid_    ) &&
      (gid_     == other.gid_    ) &&
      (euid_    == other.egid_   ) &&
      (suid_    == other.suid_   ) &&
      (fsuid_   == other.fsuid_  ) &&
      (egid_    == other.egid_   ) &&
      (sgid_    == other.sgid_   ) &&
      (fsgid_   == other.fsgid_  ));
}

void Syscall::dumpDB( sqlite3* conn,
    sqlite3_int64 rid,
    uid_t ouid,
    gid_t ogid,
    mode_t mode,
    strlut_t& strlut )
{
  assert( proc_ != NULL );

  sqlite3_int64 sc_open_id = -1;
  sqlite3_int64 sc_execve_id = -1;

  SCOpen* sco = dynamic_cast<SCOpen*>(this);
  if (sco != NULL) sc_open_id = sco->dumpDB( conn, strlut );
  SCExecve* sce = dynamic_cast<SCExecve*>(this);
  if (sce != NULL) sc_execve_id = sce->dumpDB( conn, strlut );


  sqlite3_int64 procid = proc_->dumpDB( conn, strlut );

  OpMeta ctx;
  ctx.rid             = rid;
  ctx.procid          = procid;
  ctx.sc_open_id      = sc_open_id;
  ctx.sc_execve_id    = sc_execve_id; 
  ctx.serial          = serial_;
  ctx.sec             = sec_;
  ctx.milli           = milli_;
  ctx.syscall_number  = syscall_;
  ctx.success         = success_;
  ctx.exit_code       = exit_;
  ctx.auid            = auid_;
  ctx.uid             = uid_;
  ctx.gid             = gid_;
  ctx.euid            = euid_;
  ctx.suid            = suid_;
  ctx.fsuid           = fsuid_;
  ctx.egid            = egid_;
  ctx.sgid            = sgid_;
  ctx.fsgid           = fsgid_;
  ctx.ouid            = ouid;
  ctx.ogid            = ogid;
  ctx.mode            = mode;
  sqlite3_int64 omid  = insertOpMeta( conn, ctx );
}

void Syscall::dumpDot( FILE *out,
    uid_t ouid,
    gid_t ogid,
    mode_t mode,
    strlut_t& strlut )
{
  /*
  assert( proc_ != NULL );

  sqlite3_int64 sc_open_id = -1;
  sqlite3_int64 sc_execve_id = -1;

  SCOpen* sco = dynamic_cast<SCOpen*>(this);
  if (sco != NULL) sc_open_id = sco->dumpDB( conn, strlut );
  SCExecve* sce = dynamic_cast<SCExecve*>(this);
  if (sce != NULL) sc_execve_id = sce->dumpDB( conn, strlut );


  //sqlite3_int64 procid = proc_->dumpDB( conn, strlut );

  OpMeta ctx;
  ctx.rid             = rid;
  ctx.procid          = procid;
  ctx.sc_open_id      = sc_open_id;
  ctx.sc_execve_id    = sc_execve_id; 
  ctx.serial          = serial_;
  ctx.sec             = sec_;
  ctx.milli           = milli_;
  ctx.syscall_number  = syscall_;
  ctx.success         = success_;
  ctx.exit_code       = exit_;
  ctx.auid            = auid_;
  ctx.uid             = uid_;
  ctx.gid             = gid_;
  ctx.euid            = euid_;
  ctx.suid            = suid_;
  ctx.fsuid           = fsuid_;
  ctx.egid            = egid_;
  ctx.sgid            = sgid_;
  ctx.fsgid           = fsgid_;
  ctx.ouid            = ouid;
  ctx.ogid            = ogid;
  ctx.mode            = mode;
  //sqlite3_int64 omid  = insertOpMeta( conn, ctx );
  */
}

uid_t Syscall::getUid() { return uid_; }
gid_t Syscall::getGid() { return gid_; }
uid_t Syscall::getSuid() { return suid_; }
gid_t Syscall::getSgid() { return sgid_; }
uid_t Syscall::getEuid() { return euid_; }
gid_t Syscall::getEgid() { return egid_; }
time_t Syscall::getTime() { return sec_; }
//===================================================================
//                        SCOnFile
//===================================================================

/*!
 * Calls proc connected to this syscall to purge
 * this syscall.
 * */
void SCOnFile::reversePurgeProc()
{
  proc_->purgeSyscall(this);
}

void SCOnFile::ppFile(FILE *out, strlut_t& strlut)
{
  list<FileInstance *>::iterator b, e;
  for (b = fileinstances_.begin(), e = fileinstances_.end();
      b != e; ++b)
  {
    fprintf(out, "\t%s\n", strlut[(*b)->getInstanceOf()->getFullpathHash()]);
  }
}

void SCOnFile::addFileInstance(FileInstance *instance)
{
  fileinstances_.push_back(instance);
}


//=========
// SCOpen
//=========

void SCOpen::setFlags(int flags) { flags_  = flags;  }
int SCOpen::getFlags()  { return flags_;  }


sqlite3_int64 SCOpen::dumpDB( sqlite3* conn, strlut_t& strlut )
{
  return insertSCOpen( conn, flags_ );
}


//==========
// SCExecve
//==========

/*!
 * SCExecve Destructor.
 * */
SCExecve::~SCExecve()
{
  if (args_[0] != NULL) delete [] args_[0];
  if (args_[1] != NULL) delete [] args_[1];
  if (args_[2] != NULL) delete [] args_[2];
  if (args_[3] != NULL) delete [] args_[3];
}

/*!
 * Adds argument.
 * */
void SCExecve::setArg(const int index, const char *arg)
{
  assert( args_[index] == NULL );
  assert( arg != NULL );
  args_[index] = allocCpyStrNoQuotes( arg );
}

int SCExecve::getArgc() { return argc_; }
void SCExecve::setArgc(const int argc) { argc_ = argc; }
void SCExecve::setArg0(const char *arg) { setArg(0, arg); }
void SCExecve::setArg1(const char *arg) { setArg(1, arg); }
void SCExecve::setArg2(const char *arg) { setArg(2, arg); }
void SCExecve::setArg3(const char *arg) { setArg(3, arg); }

/*!
 * Pretty prints syscall.
 * */
void SCExecve::pp(FILE *out, strlut_t& strlut)
{
  Syscall::pp(out, strlut);
  fprintf(out, "\targs=");
  for (int i = 0; i < argc_; ++i)
  {
    if (i != 0) fprintf(out, ", ");
    fprintf( out, "%s", args_[i] );
  }
  fprintf(out, "\n");
}


sqlite3_int64 SCExecve::dumpDB( sqlite3* conn, strlut_t& strlut )
{
  return insertSCExecve( conn, argc_, args_[0], args_[1], args_[2], args_[3] );
}

//===================================================================
//                        SCOnProc
//===================================================================
void SCOnProc::setTgtProc(Process *tgtproc)
{
  tgtproc_ = tgtproc;
}

Process * SCOnProc::getTgtProc()
{
  return tgtproc_;
}
