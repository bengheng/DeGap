/*
 * db.cpp
 *
 * Database updating functions.
 * */

#include <stdio.h>
#include <stdlib.h>
#include <grp.h>
#include <pwd.h>
#include <sqlite3.h>
#include <string.h>
#include <string>
#include <linux/limits.h>
#include <boost/filesystem.hpp>
#include "db.h"

using namespace std;
using namespace boost::filesystem;

#define PERR(c) \
  fprintf( stderr, "%s:%d %s\n", __FILE__, __LINE__, sqlite3_errmsg(c) );

#define ASSERT_SQLITE( c, r, e ) \
  if (r != e) { PERR( c ); exit(-1); }

#define ASSERT_OK( c, r )    ASSERT_SQLITE( c, r, SQLITE_OK   )
#define ASSERT_DONE( c, r )  ASSERT_SQLITE( c, r, SQLITE_DONE )

//#define STRLEN(s) ( (strlen(s) + 1) * sizeof(char) )
#define STRLEN(s) ( strlen(s) * sizeof(char) )

typedef enum
{
  SELECT_UNID = 0,
  SELECT_GNID,
  SELECT_RID,
  SELECT_PROGID,
  SELECT_PROCID,
  SELECT_AID,
  SELECT_SCOPENID,
  SELECT_SCEXECVEID,
  INSERT_PASSWD1,
  INSERT_PASSWD2,
  INSERT_GROUP1,
  INSERT_GROUP2,
  INSERT_GROUP_MEMBERSHIP,
  INSERT_RESOURCE,
  INSERT_PROGRAM,
  INSERT_PROCESS,
  INSERT_PRINCIPAL,
  //INSERT_OPERATION,
  INSERT_OPMETA,
  INSERT_SCOPEN,
  INSERT_SCEXECVE,
  LAST
} QUERY;
static sqlite3_stmt* stmts[LAST];

const char *s[LAST] = {
  "SELECT `unid` FROM `user_name` WHERE `name`=?",
  "SELECT `gnid` FROM `group_name` WHERE `name`=?",
  "SELECT `rid` FROM `Resource` WHERE `inode`=? AND `path`=? AND `extension`=?",
  "SELECT `progid` FROM `program` WHERE `comm`=? AND `exe`=?",
  "SELECT `procid` FROM `Process` WHERE `progid`=? AND `pid`=? AND `ppid`=?",
  "SELECT `aid` FROM `Principal` WHERE `uid`=? AND `gid`=?",
  "SELECT `sc_open_id` FROM `syscall_open` WHERE `flags`=?",
  "SELECT `sc_execve_id` FROM `syscall_execve` WHERE `argc`=? AND `arg0`=? AND `arg1`=? AND `arg2`=? AND `arg3`=?",
  "INSERT OR IGNORE INTO `user` (`uid`) VALUES (?)",
  "INSERT INTO `user_name` (`uid`, `name`, `pri_gid`) VALUES (?,?,?)",
  "INSERT OR IGNORE INTO `group` (`gid`) VALUES (?)",
  "INSERT INTO `group_name` (`gid`, `name`) VALUES (?,?)",
  "INSERT OR IGNORE INTO `group_membership` (`unid`, `gnid`) VALUES (?,?)",
  "INSERT INTO `Resource` (`inode`, `path`, `extension`) VALUES (?,?,?)",
  "INSERT INTO `program` (`comm`, `exe`) VALUES (?,?)",
  "INSERT INTO `Process` (`progid`, `pid`, `ppid`) VALUES (?,?,?)",
  "INSERT INTO `Principal` (`uid`, `gid`) VALUES (?,?)",
  //"INSERT INTO `Operation` (`label`) VALUES (?)",
  "INSERT INTO `OpMeta` (`rid`, `procid`, `sc_open_id`, `sc_execve_id`, "\
    "`serial`, `sec`, `milli`, `syscall`, `success`, `exit`, "\
    "`auid`, `uid`, `gid`, `euid`, `suid`, `fsuid`, `egid`, "\
    "`sgid`, `fsgid`,`ouid`,`ogid`,`mode`) "\
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
  "INSERT INTO `syscall_open` (`flags`) VALUES (?)",
  "INSERT INTO `syscall_execve` (`argc`, `arg0`, `arg1`, `arg2`, `arg3`) VALUES (?,?,?,?,?)",
};

void prepareDb( sqlite3* conn )
{
  int rc;
  char* errmsg;

  // Trust the OS to handle the data. If the machine crashes, we're toast.
  // But we're not operating a space station.
  rc = sqlite3_exec( conn, "PRAGMA synchronous = OFF", NULL, NULL, &errmsg);
  if (rc != SQLITE_OK) {
    fprintf( stderr, "Database Error! %s\n", errmsg );
    sqlite3_free( errmsg );
    exit( -1 );
  }

  // Keep rollback journal in memory
  sqlite3_exec( conn, "PRAGMA journal_mode = MEMORY", NULL, NULL, &errmsg);
  if (rc != SQLITE_OK) {
    fprintf( stderr, "Database Error! %s\n", errmsg );
    sqlite3_free( errmsg );
    exit( -1 );
  }

  for (int i = 0; i < LAST; ++i) {
    rc = sqlite3_prepare_v2( conn, s[i], STRLEN(s[i]), &stmts[i], NULL );
    ASSERT_OK( conn, rc );
  }
}

void finalizeDb( void )
{
  for (int i = 0; i < LAST; ++i)
    sqlite3_finalize( stmts[i] );
}

void beginTransaction( sqlite3* conn )
{
  int rc;
  char* errmsg;
  rc = sqlite3_exec( conn, "BEGIN TRANSACTION", NULL, NULL, &errmsg );
  if (rc != SQLITE_OK)
  {
    fprintf( stderr, "%s:%d %s\n", __FILE__, __LINE__, errmsg );
    sqlite3_free(errmsg);
    exit( -1 );
  }
}

void endTransaction( sqlite3* conn )
{
  int rc;
  char* errmsg;

  rc = sqlite3_exec( conn, "END TRANSACTION", NULL, NULL, &errmsg );
  if (rc != SQLITE_OK)
  {
    fprintf( stderr, "%s:%d %s\n", __FILE__, __LINE__, errmsg );
    sqlite3_free(errmsg);
    exit( -1 );
  }
}


//========== type ==========
//

/*
 * Returns the first column item after making query q described by s.
 *
 * Typically used for getting index of entries described by s.
 * */
static sqlite3_int64 selectXid( sqlite3* conn, const char* s, QUERY q )
{
  int rc;
  sqlite3_stmt* st = stmts[q];
  sqlite3_int64 xid = -1;

  rc = sqlite3_bind_text( st, 1, s, STRLEN(s), SQLITE_STATIC);
  ASSERT_OK( conn, rc );

  rc = sqlite3_step( st );
  switch (rc)
  {
    case SQLITE_ROW:
      xid = sqlite3_column_int64( st, 0 );
      break;
    case SQLITE_DONE: break;
    default: PERR( conn ); exit(-1);
  }

  sqlite3_clear_bindings( st );
  sqlite3_reset( st );

  return xid;
}


//========== users, groups ==========
//

/*
 * This function should come after insertGroup so that the user's
 * primary group id can be found.
 * */
void insertPasswd( sqlite3* conn, const char* passwd_fname )
{
  beginTransaction( conn );

  FILE *pwd_file = fopen(passwd_fname, "r");
  if (pwd_file == NULL)
  {
    fprintf(stderr, "FATAL: Can't read \"%s\".", passwd_fname);
    endTransaction( conn );
    return;
  }

  int rc;

  sqlite3_stmt* st1 = stmts[INSERT_PASSWD1];
  sqlite3_stmt* st2 = stmts[INSERT_PASSWD2];

  // Read each entry of password file
  struct passwd *pwd = NULL;
  while ((pwd = fgetpwent(pwd_file)) != NULL)
  {
    // "INSERT OR IGNORE INTO `user` (`uid`) VALUES (%d)", pwd->pw_uid );
    rc = sqlite3_bind_int( st1, 1, pwd->pw_uid );
    ASSERT_OK( conn, rc );
    rc = sqlite3_step( st1 );
    ASSERT_DONE( conn, rc );
    sqlite3_clear_bindings( st1 );
    sqlite3_reset( st1 );

    // "INSERT INTO `user_name` (`uid`, `name`, `pri_gid`) VALUES (%d, \"%s\", %d)",
    //    pwd->pw_uid, pwd->pw_name, pwd->pw_gid );
    rc = sqlite3_bind_int( st2, 1, pwd->pw_uid );
    ASSERT_OK( conn, rc );
    rc = sqlite3_bind_text( st2, 2, pwd->pw_name, STRLEN( pwd->pw_name ), SQLITE_STATIC );
    ASSERT_OK( conn, rc );
    rc = sqlite3_bind_int( st2, 3, pwd->pw_gid );
    ASSERT_OK( conn, rc );
    rc = sqlite3_step( st2 );
    ASSERT_DONE( conn, rc );
    sqlite3_clear_bindings( st2 );
    sqlite3_reset( st2 );
  }

  fclose(pwd_file);
  endTransaction( conn );
}


/*
 * This function should come before insertPasswd so that the
 * primary group id for the user can be found.
 * */
void insertGroup( sqlite3* conn, const char* group_fname )
{
  FILE *grp_file = fopen(group_fname, "r");
  if (grp_file == NULL)
  {
    fprintf(stderr, "FATAL: Can't read \"%s\".", group_fname);
    return;
  }

  int rc;
  char *errmsg;
  rc = sqlite3_exec( conn, "BEGIN TRANSACTION", NULL, NULL, &errmsg );
  if (rc != SQLITE_OK)
  {
    fprintf( stderr, "%s:%d %s\n", __FILE__, __LINE__, errmsg );
    sqlite3_free(errmsg);
    fclose( grp_file );
    exit( -1 );
  }

  sqlite3_stmt* st1 = stmts[INSERT_GROUP1];
  sqlite3_stmt* st2 = stmts[INSERT_GROUP2];

  // Read each entry of group file and insert into db.
  // We have to split up gr_gid and gr_name into two tables because it is possible
  // to have two group names sharing the same gid. >=(
  struct group *grp = NULL;
  while ((grp = fgetgrent(grp_file)) != NULL)
  {
    // "INSERT OR IGNORE INTO `group` (`gid`) VALUES (%d)", grp->gr_gid );
    rc = sqlite3_bind_int( st1, 1, grp->gr_gid ); ASSERT_OK( conn, rc );
    rc = sqlite3_step( st1 );                     ASSERT_DONE( conn, rc );
    sqlite3_clear_bindings( st1 );
    sqlite3_reset( st1 );

    // "INSERT INTO `group_name` (`gid`, `name`) VALUES (%d, \"%s\")",
    //    grp->gr_gid, grp->gr_name );
    rc = sqlite3_bind_int( st2, 1, grp->gr_gid );
    ASSERT_OK( conn, rc );
    rc = sqlite3_bind_text( st2, 2, grp->gr_name, STRLEN( grp->gr_name ), SQLITE_STATIC );
    ASSERT_OK( conn, rc );
    rc = sqlite3_step( st2 );
    ASSERT_DONE( conn, rc );
    sqlite3_clear_bindings( st2 );
    sqlite3_reset( st2 );
  }

  fclose(grp_file);

  rc = sqlite3_exec( conn, "END TRANSACTION", NULL, NULL, &errmsg );
  if (rc != SQLITE_OK)
  {
    fprintf( stderr, "%s:%d %s\n", __FILE__, __LINE__, errmsg );
    sqlite3_free(errmsg);
    exit( -1 );
  }
}

/*
 * This needs to come after insertPasswd and insertGroup, since it depends
 * on the uids and gids.
 * */
void insertGroupMemberships( sqlite3* conn, const char* group_fname )
{

  FILE *grp_file = fopen(group_fname, "r");
  if (grp_file == NULL)
  {
    fprintf(stderr, "FATAL: Can't read \"%s\".", group_fname);
    return;
  }

  int rc;
  char *errmsg;
  rc = sqlite3_exec( conn, "BEGIN TRANSACTION", NULL, NULL, &errmsg );
  if (rc != SQLITE_OK)
  {
    fprintf( stderr, "%s:%d %s\n", __FILE__, __LINE__, errmsg );
    sqlite3_free(errmsg);
    fclose( grp_file );
    exit( -1 );
  }

  sqlite3_stmt* st = stmts[INSERT_GROUP_MEMBERSHIP];

  // Read each entry of group file
  struct group *grp = NULL;
  while ((grp = fgetgrent(grp_file)) != NULL)
  {

    sqlite3_int64 gnid = selectXid( conn, grp->gr_name, SELECT_GNID );

    // Add members
    char **mem = grp->gr_mem;
    for (; *mem != NULL; mem++)
    {
      sqlite3_int64 unid = selectXid( conn, *mem, SELECT_UNID );

      if ( unid == (sqlite3_int64) -1 )
        continue;
      // rc = sqlite3_bind_null( st, 1 );
      else
        rc = sqlite3_bind_int64( st, 1, unid );
      ASSERT_OK( conn, rc );

      rc = sqlite3_bind_int64( st, 2, gnid );
      ASSERT_OK( conn, rc );

      rc = sqlite3_step( st );
      if (rc != SQLITE_DONE)
      {
        fprintf( stderr, "%s:%d %s unid=%d (%s) gnid=%d (%s)\n",
            __FILE__, __LINE__, s[INSERT_GROUP_MEMBERSHIP],
            unid, *mem, gnid, grp->gr_name);
        PERR( conn );
        exit( -1 );
      }

      sqlite3_reset( st );
      sqlite3_clear_bindings( st );
    }
  }
  fclose(grp_file);

  rc = sqlite3_exec( conn, "END TRANSACTION", NULL, NULL, &errmsg );
  if (rc != SQLITE_OK)
  {
    fprintf( stderr, "%s:%d %s\n", __FILE__, __LINE__, errmsg );
    sqlite3_free(errmsg);
    exit( -1 );
  }
}

//========== file_properties ==========
//

/*
 * Returns rmid for resource metadata.
 * */
static sqlite3_int64 selectRid( sqlite3* conn,
    int inode, const char* path, const char* extension )
{
  int rc;
  sqlite3_stmt* st = stmts[SELECT_RID];
  sqlite3_int64 rmid = -1;

  rc = sqlite3_bind_int( st, 1, inode );
  ASSERT_OK( conn, rc );

  if (path != NULL) {
    rc = sqlite3_bind_text( st, 2, path, STRLEN(path), SQLITE_STATIC);
    ASSERT_OK( conn, rc );
  }
  if (extension != NULL) {
    rc = sqlite3_bind_text( st, 3, extension, STRLEN(extension), SQLITE_STATIC);
    ASSERT_OK( conn, rc );
  }

  rc = sqlite3_step( st );
  switch (rc)
  {
    case SQLITE_ROW:
      rmid = sqlite3_column_int64( st, 0 );
      break;
    case SQLITE_DONE: break;
    default: PERR( conn ); exit(-1);
  }

  sqlite3_clear_bindings( st );
  sqlite3_reset( st );

  return rmid;
}


sqlite3_int64 insertResource(
    sqlite3* conn,
    int inode,
    const char* path,
    const char* extension )
{
  sqlite3_int64 rid = selectRid( conn, inode, path, extension );
  if (rid != (sqlite3_int64) -1) return rid;

  int rc;
  sqlite3_stmt* st = stmts[INSERT_RESOURCE];

  rc = sqlite3_bind_int( st, 1, inode );
  ASSERT_OK( conn, rc );
  if (path == NULL)
    rc = sqlite3_bind_null( st, 2 );
  else
    rc = sqlite3_bind_text( st, 2, path, STRLEN( path ), SQLITE_STATIC );
  ASSERT_OK( conn, rc );
  if (extension == NULL)
    rc = sqlite3_bind_null( st, 3 );
  else
    rc = sqlite3_bind_text( st, 3, extension, STRLEN( extension ), SQLITE_STATIC );
  ASSERT_OK( conn, rc );

  rc = sqlite3_step( st );
  ASSERT_DONE( conn, rc );

  sqlite3_reset( st );
  sqlite3_clear_bindings( st );

  return sqlite3_last_insert_rowid(conn);
}


//========== program ==========
//

/*
 * Returns progid for program having comm and exe.
 * */
static sqlite3_int64 getProgid( sqlite3* conn,
    const char* comm, const char* exe )
{
  int rc;
  sqlite3_stmt* st = stmts[SELECT_PROGID];
  sqlite3_int64 progid = -1;

  if (comm != NULL) {
    rc = sqlite3_bind_text( st, 1, comm, STRLEN(comm), SQLITE_STATIC);
    ASSERT_OK( conn, rc );
  }
  if (exe != NULL) {
    rc = sqlite3_bind_text( st, 2, exe, STRLEN(exe), SQLITE_STATIC);
    ASSERT_OK( conn, rc );
  }

  rc = sqlite3_step( st );
  switch (rc)
  {
    case SQLITE_ROW:
      progid = sqlite3_column_int64( st, 0 );
      break;
    case SQLITE_DONE: break;
    default: PERR( conn ); exit(-1);
  }

  sqlite3_reset( st );
  sqlite3_clear_bindings( st );

  return progid;
}


sqlite3_int64 insertProgram(
    sqlite3* conn,
    const char* comm,
    const char* exe )
{
  sqlite3_int64 progid = getProgid( conn, comm, exe );
  if (progid != (sqlite3_int64) -1) {
    return progid;
  }

  int rc;
  sqlite3_stmt* st = stmts[INSERT_PROGRAM];

  if (comm != NULL) {
    rc = sqlite3_bind_text( st, 1, comm, STRLEN(comm), SQLITE_STATIC);
    ASSERT_OK( conn, rc );
  }

  if (exe != NULL) {
    rc = sqlite3_bind_text( st, 2, exe, STRLEN(exe), SQLITE_STATIC);
    ASSERT_OK( conn, rc );
  }

  rc = sqlite3_step( st );
  ASSERT_DONE( conn, rc );

  sqlite3_reset( st );
  sqlite3_clear_bindings( st );
  
  return sqlite3_last_insert_rowid(conn);
}

//========== process ==========
//

/*
 * Returns procid for process.
 * */
static sqlite3_int64 getProcid( sqlite3* conn,
    sqlite3_int64 progid,
    pid_t pid,
    pid_t ppid )
{
  int rc;
  sqlite3_stmt* st = stmts[SELECT_PROCID];
  sqlite3_int64 procid = -1;

  rc = sqlite3_bind_int64( st, 1, progid ); ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 2, pid );      ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 3, ppid );     ASSERT_OK( conn, rc );

  rc = sqlite3_step( st );
  switch (rc)
  {
    case SQLITE_ROW:
      procid = sqlite3_column_int64( st, 0 );
      break;
    case SQLITE_DONE: break;
    default: PERR( conn ); exit(-1);
  }

  sqlite3_reset( st );
  sqlite3_clear_bindings( st );

  return procid;
}


sqlite3_int64 insertProcess(
    sqlite3* conn,
    sqlite3_int64 progid,
    pid_t pid,
    pid_t ppid )
{
  sqlite3_int64 procid = getProcid( conn, progid, pid, ppid );
  if (procid != (sqlite3_int64) -1) return procid;

  int rc;
  sqlite3_stmt* st = stmts[INSERT_PROCESS];

  rc = sqlite3_bind_int64( st, 1, progid ); ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 2, pid );      ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 3, ppid );     ASSERT_OK( conn, rc );

  rc = sqlite3_step( st );
  ASSERT_DONE( conn, rc );

  sqlite3_reset( st );
  sqlite3_clear_bindings( st );

  return sqlite3_last_insert_rowid(conn);
}

//========== Principal ==========

static void insertUser( sqlite3* conn,
    uid_t uid )
{
  int rc;
  sqlite3_stmt* st = stmts[INSERT_PASSWD1];

  rc = sqlite3_bind_int( st, 1, uid ); ASSERT_OK( conn, rc );
  rc = sqlite3_step( st );             ASSERT_DONE( conn, rc );
  sqlite3_reset( st );
  sqlite3_clear_bindings( st );
}

static void insertGroup( sqlite3* conn,
    gid_t gid )
{
  int rc;
  sqlite3_stmt* st = stmts[INSERT_GROUP1];

  rc = sqlite3_bind_int( st, 1, gid ); ASSERT_OK( conn, rc );
  rc = sqlite3_step( st );             ASSERT_DONE( conn, rc );
  sqlite3_reset( st );
  sqlite3_clear_bindings( st );
}

static sqlite3_int64 getAid( sqlite3* conn,
    uid_t uid,
    gid_t gid )
{
  int rc;
  sqlite3_stmt* st = stmts[SELECT_AID];
  sqlite3_int64 aid = -1;

  rc = (uid == (uid_t)-1)
    ? sqlite3_bind_null( st, 1 )
    : sqlite3_bind_int( st, 1, uid );
  ASSERT_OK( conn, rc );

  rc = (gid == (gid_t)-1)
    ? sqlite3_bind_null( st, 2 )
    : sqlite3_bind_int( st, 2, gid );
  ASSERT_OK( conn, rc );

  rc = sqlite3_step( st );
  switch (rc)
  {
    case SQLITE_ROW:
      aid = sqlite3_column_int64( st, 0 );
      break;
    case SQLITE_DONE: break;
    default: PERR( conn ); exit(-1);
  }

  sqlite3_clear_bindings( st );
  sqlite3_reset( st );

  return aid;
}

sqlite3_int64 insertPrincipal(
    sqlite3* conn,
    uid_t uid,
    gid_t gid )
{
  int rc;
  sqlite3_int64 aid;

  insertUser( conn, uid );
  insertGroup( conn, gid );

  aid = getAid( conn, uid, gid );
  if ( aid != (sqlite3_int64) -1 ) return aid;

  sqlite3_stmt* st = stmts[INSERT_PRINCIPAL];

  if (uid != (uid_t)-1) {
    rc = sqlite3_bind_int( st, 1, uid );
    ASSERT_OK( conn, rc );
  }
  if (gid != (gid_t)-1) {
    rc = sqlite3_bind_int( st, 2, gid );
    ASSERT_OK( conn, rc );
  }

  rc = sqlite3_step( st );
  ASSERT_DONE( conn, rc );

  sqlite3_clear_bindings( st );
  sqlite3_reset( st );

  return sqlite3_last_insert_rowid(conn);
}


//========== Operation ==========

sqlite3_int64 insertOpMeta( sqlite3* conn, OpMeta& ctx )
{
  int rc;
  sqlite3_stmt* st = stmts[INSERT_OPMETA];

  rc = sqlite3_bind_int64( st, 1, ctx.rid );
  ASSERT_OK( conn, rc );

  rc = sqlite3_bind_int64( st, 2, ctx.procid );
  ASSERT_OK( conn, rc );
  if (ctx.sc_open_id != (sqlite3_int64)-1) {
    rc = sqlite3_bind_int64( st, 3, ctx.sc_open_id );
    ASSERT_OK( conn, rc );
  }
  if (ctx.sc_execve_id != (sqlite3_int64)-1) {
    rc = sqlite3_bind_int64( st, 4, ctx.sc_execve_id );
    ASSERT_OK( conn, rc );
  }
  rc = sqlite3_bind_int64( st, 5, ctx.serial );       ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int64( st, 6, ctx.sec );          ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 7, ctx.milli );          ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 8, ctx.syscall_number ); ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 9, ctx.success );        ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 10, ctx.exit_code );     ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 11, ctx.auid );          ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 12, ctx.uid );           ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 13, ctx.gid );           ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 14, ctx.euid );          ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 15, ctx.suid );          ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 16, ctx.fsuid );         ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 17, ctx.egid );          ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 18, ctx.sgid );          ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 19, ctx.fsgid );         ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 20, ctx.ouid );          ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 21, ctx.ogid );          ASSERT_OK( conn, rc );
  rc = sqlite3_bind_int( st, 22, ctx.mode );          ASSERT_OK( conn, rc );

  rc = sqlite3_step( st );
  ASSERT_DONE( conn, rc );

  sqlite3_clear_bindings( st );
  sqlite3_reset( st );

  return sqlite3_last_insert_rowid(conn);
}



//========== scopen, scexecve ==========

static sqlite3_int64 selectScOpenId( sqlite3* conn,
    const int flags )
{
  int rc;
  sqlite3_stmt* st = stmts[SELECT_SCOPENID];
  sqlite3_int64 scopenid = -1;

  rc = sqlite3_bind_int( st, 1, flags );
  ASSERT_OK( conn, rc );

  rc = sqlite3_step( st );
  switch (rc)
  {
    case SQLITE_ROW:
      scopenid = sqlite3_column_int64( st, 0 );
      break;
    case SQLITE_DONE: break;
    default: PERR( conn ); exit(-1);
  }

  sqlite3_clear_bindings( st );
  sqlite3_reset( st );

  return scopenid;
}


sqlite3_int64 insertSCOpen( sqlite3* conn,
    int flags )
{
  sqlite3_int64 scopenid = selectScOpenId( conn, flags );
  if (scopenid != (sqlite3_int64) -1) return scopenid;

  int rc;
  sqlite3_stmt* st = stmts[INSERT_SCOPEN];

  rc = sqlite3_bind_int( st, 1, flags ); ASSERT_OK( conn, rc );
  rc = sqlite3_step( st );               ASSERT_DONE( conn, rc );

  sqlite3_clear_bindings( st );
  sqlite3_reset( st );

  return sqlite3_last_insert_rowid(conn);
}


static sqlite3_int64 selectScExecveId( sqlite3* conn,
    const int argc,
    const char* arg0,
    const char* arg1,
    const char* arg2,
    const char* arg3 )
{
  int rc;
  sqlite3_stmt* st = stmts[SELECT_SCEXECVEID];
  sqlite3_int64 scexecveid = -1;

  rc = sqlite3_bind_int( st, 1, argc );
  ASSERT_OK( conn, rc );
  if (arg0 != NULL) {
    rc = sqlite3_bind_text( st, 2, arg0, STRLEN(arg0), SQLITE_STATIC);
    ASSERT_OK( conn, rc );
  }
  if (arg1 != NULL) {
    rc = sqlite3_bind_text( st, 3, arg1, STRLEN(arg1), SQLITE_STATIC);
    ASSERT_OK( conn, rc );
  }
  if (arg2 != NULL) {
    rc = sqlite3_bind_text( st, 4, arg2, STRLEN(arg2), SQLITE_STATIC);
    ASSERT_OK( conn, rc );
  }
  if (arg3 != NULL) {
    rc = sqlite3_bind_text( st, 5, arg3, STRLEN(arg3), SQLITE_STATIC);
    ASSERT_OK( conn, rc );
  }


  rc = sqlite3_step( st );
  switch (rc)
  {
    case SQLITE_ROW:
      scexecveid = sqlite3_column_int64( st, 0 );
      break;
    case SQLITE_DONE: break;
    default: PERR( conn ); exit(-1);
  }

  sqlite3_clear_bindings( st );
  sqlite3_reset( st );

  return scexecveid;
}

sqlite3_int64 insertSCExecve( sqlite3* conn,
    const int argc,
    const char* arg0,
    const char* arg1,
    const char* arg2,
    const char* arg3 )
{
  sqlite3_int64 scexecveid = selectScExecveId( conn, argc, arg0, arg1, arg2, arg3 );
  if (scexecveid != (sqlite3_int64) -1) return scexecveid;

  int rc;
  sqlite3_stmt* st = stmts[INSERT_SCEXECVE];

  rc = sqlite3_bind_int( st, 1, argc);
  ASSERT_OK( conn, rc );

  if (arg0 != NULL) {
    rc = sqlite3_bind_text( st, 2, arg0, STRLEN(arg0), SQLITE_STATIC);
    ASSERT_OK( conn, rc );
  }

  if (arg1 != NULL) {
    rc = sqlite3_bind_text( st, 3, arg1, STRLEN(arg1), SQLITE_STATIC);
    ASSERT_OK( conn, rc );
  }

  if (arg2 != NULL) {
    rc = sqlite3_bind_text( st, 4, arg2, STRLEN(arg2), SQLITE_STATIC);
    ASSERT_OK( conn, rc );
  }

  if (arg3 != NULL) {
    rc = sqlite3_bind_text( st, 5, arg3, STRLEN(arg3), SQLITE_STATIC);
    ASSERT_OK( conn, rc );
  }

  rc = sqlite3_step( st );
  ASSERT_DONE( conn, rc );

  sqlite3_clear_bindings( st );
  sqlite3_reset( st );

  return sqlite3_last_insert_rowid(conn);
}
