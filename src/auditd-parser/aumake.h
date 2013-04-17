#ifndef __AUMAKE_HEADER__
#define __AUMAKE_HEADER__

#include <set>
#include <list>
#include <algorithm>
#include <unordered_map>
#include <assert.h>
#include <string>
#include <semaphore.h>
#include <pthread.h>
#include "process.h"
#include "progfile.h"
#include "file.h"
#include "syscall.h"
#include "utilities.h"
#include "strhash.h"

typedef unsigned long serial_t;

typedef struct
{
  bool                      bad;
  pthread_t                 thread_id;
  std::list< std::pair<int, char*> > records;
  time_t                    sec;
  unsigned int              milli;
  serial_t                  serial;
  int                       items;
  std::string               cwd;
  Process*                  process;
  Syscall*                  syscall;
  std::unordered_map< long, std::list<FileInstance *>* >  file_instances;
} EVENT, *PEVENT;

int aumake(
    const char **audit_logs,
    const SCNUM &scnum,
    strlut_t &strlut,
    ProgFile &rootprog,
    File &rootfile,
    std::list<std::string *> &ignore_paths,
    std::set<Syscall*> &syscalls );

void audestroy();

/*!
 * Prints event syscall.
 * */
struct ppEvent {
  strlut_t* strlut_;
  ppEvent(strlut_t* strlut) : strlut_(strlut) {}
  void operator() (std::pair<serial_t, PEVENT> entry) const
  {
    PEVENT evt = entry.second;
    evt->syscall->pp(stdout, *strlut_);
  }
};

/*
struct delSingleEvent
{
  delSingleEvent() {}
  void operator() (PEVENT pevt)
  {
    if (pevt->syscall != NULL)
    {
      SCOpen *sco = NULL;
      SCExecve *sce = NULL;
      if ( (sco = dynamic_cast<SCOpen *>(pevt->syscall)) != NULL )
      {
        delete sco;
        pevt->syscall = NULL;
      }
      else if ( (sce = dynamic_cast<SCExecve *>(pevt->syscall)) != NULL )
      {
        delete sce;
        pevt->syscall = NULL;
      }
      else
      {
        assert(0);
      }

      //BOOST_FOREACH(FileInstance *fi, pevt->file_instances)
      //{ delete fi; }
    }
    //fprintf(stderr, "DEBUG Deleting single event %08x\n", pevt);

    delete pevt;
  }
};

struct delEvent
{
  delEvent() {}
  void operator() (std::pair<serial_t, std::list<PEVENT>* > entry)
  {
    std::list<PEVENT> *pevtlist = entry.second;
    for_each(pevtlist->begin(), pevtlist->end(), delSingleEvent());
    delete pevtlist;
  }
};
*/

#endif
