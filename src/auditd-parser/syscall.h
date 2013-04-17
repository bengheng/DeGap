#ifndef __AUSYSCALL_HEADER__
#define __AUSYSCALL_HEADER__

#include <typeinfo>
#include <sqlite3.h>
#include <time.h>
#include "utilities.h"
#include "file.h"
#include "strhash.h"

/*

                Syscall
                   |
          --------------------
          |                  |
       SCOnFile          SCOnProc
          |                  |
      ---------       ----------------
      |       |       |       |      |
   SCOpen SCExecve SCClone SCFork SCVfork
*/

// Forward declarations
class Process;
class File;

class Syscall
{
  public:
    Syscall(int scnum, time_t sec, unsigned int milli, serial_t serial);
    virtual ~Syscall() {};
    void setSyscallnum(int syscallnum);
    void setSuccess(const char *success);
    void setExit(int exit);
    void setAuid(int auid);
    void setUid(uid_t uid);
    void setGid(gid_t gid);
    void setEuid(uid_t euid);
    void setSuid(uid_t suid);
    void setFsuid(uid_t fsuid);
    void setEgid(gid_t egid);
    void setSgid(gid_t sgid);
    void setFsgid(gid_t fsgid);
    void setProcess(Process *proc);

    serial_t      getSerial();
    Process *     getProcess();
    uid_t         getUid();
    gid_t         getGid();
    uid_t         getSuid();
    gid_t         getSgid();
    uid_t         getEuid();
    gid_t         getEgid();
    bool          getSuccess();
    time_t        getTime();

    virtual void  pp(FILE* out, strlut_t& strlut);
    virtual bool  operator==(Syscall &other) const;

    void dumpDB( sqlite3* conn,
        sqlite3_int64 rid,
        uid_t uid,
        gid_t gid,
        mode_t mode,
        strlut_t& strlut );

    void dumpDot( FILE *out,
        uid_t uid,
        gid_t gid,
        mode_t mode,
        strlut_t& strlut );

  protected:
    time_t        sec_;     // Event seconds
    unsigned int  milli_;   // millisecond of the timestamp
    serial_t      serial_;  // Serial number of the event
    int           syscall_; // syscall number
    bool          success_; // true if success
    int           exit_;    // exit value
    int           auid_;    // audit ID
    uid_t         uid_;     // user ID
    gid_t         gid_;     // group ID
    uid_t         euid_;    // effective user ID
    uid_t         suid_;    // set user ID
    uid_t         fsuid_;   // file system user ID
    gid_t         egid_;    // effective group ID
    gid_t         sgid_;    // set group ID
    gid_t         fsgid_;   // file system group ID
    Process       *proc_;
};

//===================================================================
//                        SCOnFile
//===================================================================

typedef enum
{
  sc_owner = 0,
  sc_group,
  sc_other
} usrtype_t;

class SCOnFile : public Syscall
{
  public:
    SCOnFile(int scnum, time_t sec, unsigned int milli, unsigned long serial)
      : Syscall(scnum, sec, milli, serial) {}
    ~SCOnFile() {}

    void addFileInstance(FileInstance *instance);
    std::list<FileInstance *> &getFileInstances() { return fileinstances_; }
    void ppFile(FILE *out, strlut_t &strlut);
    void reversePurgeProc();

  private:
    std::list<FileInstance *> fileinstances_;

};

//========
// SCOpen
//========
class SCOpen : public SCOnFile
{
  public:
    SCOpen(int scnum, time_t sec, unsigned int milli, unsigned long serial)
      : SCOnFile(scnum, sec, milli, serial) {}
    ~SCOpen() {}

    void    setFlags(int flags);
    int     getFlags();
    sqlite3_int64 dumpDB( sqlite3* conn, strlut_t& strlut );

  private:
    int flags_;
};

//==========
// SCExecve
//==========
class SCExecve : public SCOnFile
{
  public:
    SCExecve(int scnum, time_t sec, unsigned int milli, unsigned long serial)
      : SCOnFile(scnum, sec, milli, serial) {
        argc_ = 0;
        args_[0] = NULL;
        args_[1] = NULL;
        args_[2] = NULL;
        args_[3] = NULL;
      }
    ~SCExecve();

    void pp(FILE *out, strlut_t& strlut);
    int getArgc();
    void setArgc(const int argc);
    void setArg0(const char* arg);
    void setArg1(const char* arg);
    void setArg2(const char* arg);
    void setArg3(const char* arg);
    sqlite3_int64 dumpDB( sqlite3* conn, strlut_t& strlut );

  private:
    int   argc_;
    char* args_[4];

    void setArg(const int index, const char *arg);
};

//===================================================================
//                        SCOnProc
//===================================================================
class SCOnProc : public Syscall
{
  public:
    SCOnProc(int scnum, time_t sec, unsigned int milli, unsigned long serial)
      : Syscall(scnum, sec, milli, serial) {}

    void setTgtProc(Process *tgtproc);
    Process * getTgtProc();

  private:
    Process *tgtproc_;
};

//==========
// SCFork
//==========
class SCFork : public SCOnProc
{
  public:
    SCFork(int scnum, time_t sec, unsigned int milli, unsigned long serial)
      : SCOnProc(scnum, sec, milli, serial) {}
    ~SCFork() {};
  private:
};

//================

/*!
 * Compares two syscalls.
 * */
struct cmpSyscall
{
  Syscall *other_;
  cmpSyscall(Syscall *other) : other_(other){}

  bool operator() (Syscall *sc)
  {
    return (typeid(*sc) == typeid(*other_) &&
        *sc == *other_);
  }
};

/*!
 * Prints syscall.
 * */
struct ppSyscall {
  strlut_t* strlut_;
  ppSyscall(strlut_t* strlut) : strlut_(strlut) {}
  void operator() (Syscall *sc) const
  {
    sc->pp(stdout, *strlut_);
  }
};

/*!
 * Deletes syscall.
 * */
struct delSyscall {
  delSyscall() {}
  void operator() (Syscall *sc) const
  {
    SCExecve *scexe = dynamic_cast<SCExecve *>(sc);
    if (scexe != NULL)
      delete scexe;
    else
      delete sc;
  }
};


#endif
