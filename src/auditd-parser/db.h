#ifndef __DB_HEADER__
#define __DB_HEADER__

#include <sqlite3.h>
#include <linux/types.h>
#include <string>
#include <boost/filesystem.hpp>

void beginTransaction( sqlite3* conn );
void endTransaction( sqlite3* conn );
void prepareDb( sqlite3* conn );
void finalizeDb( void );

void insertPasswd( sqlite3* conn, const char* passwd_fname );
void insertGroup( sqlite3* conn, const char* group_fname );
void insertGroupMemberships( sqlite3* conn, const char* group_fname );

sqlite3_int64 insertType( sqlite3* conn, const char* desc );

sqlite3_int64 insertResource(
    sqlite3* conn,
    int inode,
    const char* path,
    const char* extension );

sqlite3_int64 insertProgram(
    sqlite3* conn,
    const char* comm,
    const char* exe );

sqlite3_int64 insertProcess(
    sqlite3* conn,
    sqlite3_int64 progid,
    pid_t pid,
    pid_t ppid );

sqlite3_int64 insertPrincipal(
    sqlite3* conn,
    uid_t uid,
    gid_t gid );

typedef struct _OpMeta {
  sqlite3_int64 rid;
  sqlite3_int64 procid;
  sqlite3_int64 sc_open_id;
  sqlite3_int64 sc_execve_id;
  unsigned long serial;
  time_t sec;
  unsigned int milli;
  int syscall_number;
  bool success;
  int exit_code;
  int auid;
  uid_t uid;
  gid_t gid;
  uid_t euid;
  uid_t suid;
  uid_t fsuid;
  gid_t egid;
  gid_t sgid;
  gid_t fsgid;
  uid_t ouid;
  gid_t ogid;
  mode_t mode;
} OpMeta;

sqlite3_int64 insertOpMeta( sqlite3* conn, OpMeta& ctx);

sqlite3_int64 insertSCOpen( sqlite3* conn,
    int flags );

sqlite3_int64 insertSCExecve( sqlite3* conn,
    const int argc,
    const char* arg0,
    const char* arg1,
    const char* arg2,
    const char* arg3 );

#endif
