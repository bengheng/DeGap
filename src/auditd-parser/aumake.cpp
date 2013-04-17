#include "aussemble.h"

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


//-------------------------------------------------------------------

//-------------------------------------------------------------------

/*!
 * Main function that makes programs, files, and syscalls
 * from the audit log.
 *
 * Returns 0 on success, -1 on error.
 * */
int aumake(
    const char **audit_logs,
    const SCNUM &scnum,
    strlut_t &strlut,
    ProgFile &rootprog,
    File &rootfile,
    list<string *> &ignore_paths,
    set<Syscall*> &syscalls )

{
  auparse_state_t *au = auparse_init(AUSOURCE_FILE_ARRAY, audit_logs);
  if (au == NULL)
  {
    fprintf(stderr, "Error opening log.\n");
    return -1;
  }

  // Repositions cursors to first field of the first record
  // of the event containing the items searched for.
  if (ausearch_set_stop(au, AUSEARCH_STOP_EVENT) != 0)
  {
    fprintf(stderr, "Error setting cursor position.\n");
    auparse_destroy(au);
    return -1;
  }

  int nprocs = sysconf( _SC_NPROCESSORS_ONLN );

  list<PEVENT> events;
  getEvent(nprocs, strlut, au, scnum, rootprog, rootfile, ignore_paths, events);
  fprintf(stderr, "DEBUG Begin assembly on %d events...\n", events.size());
  assemble(nprocs, strlut, events, syscalls, rootfile);


  // Print processes
  //for_each(programs.begin(), programs.end(), ppProg());
  //fprintf(stdout, "Total # of programs: %zu\n", programs.size());

  // Print event syscalls
  //for_each(events.begin(), events.end(), ppEvent());
  //fprintf(stdout, "Total # of events: %zu\n", events.size());

  auparse_destroy(au);  

  return 0;
}


/*!
 * Releases memory for objects.
 * */
void audestroy()
{
}
