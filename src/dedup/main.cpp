#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <boost/foreach.hpp>
#include <boost/filesystem.hpp>
#include <list>

#include "dedup.h"
#include "auread.h"

using namespace std;
using namespace boost::filesystem;

/*
 * Returns type for s.
 * */
int get_type(const char* s)
{
  if (strstr(s, "type=SYSCALL ") == s) return AUDIT_SYSCALL;
  else if (strstr(s, "type=EXECVE ") == s) return AUDIT_EXECVE;
  else if (strstr(s, "type=CWD ") == s) return AUDIT_CWD;
  else if (strstr(s, "type=PATH ") == s) return AUDIT_PATH;
  return -1;
}


/*
 * Allocate and populate important fields of a auditd_reply_list
 * structure using s. Caller must free this structure.
 * */
struct auditd_reply_list* make_reply_from_line(const char* s)
{
  struct auditd_reply_list* rep
    = (struct auditd_reply_list*) malloc( sizeof(struct auditd_reply_list) );

  strcpy(rep->reply.msg.data, s);

  rep->reply.type = get_type(s);

  // only copy s beginning after "msg="
  //const char* m = "msg=";
  //char *b = strstr(s, m) + strlen(m);

  // Now requires whole string...
  const char* b = s;
  //rep->reply.len = strlen( b );
  //rep->reply.message = (const char*) malloc( rep->reply.len + 1 );
  //strncpy((char*)rep->reply.message, b, rep->reply.len);
  strncpy( rep->reply.msg.data, b, strlen( b ));

  return rep;
}

void getArgs(
    int argc,
    char **argv,
    char ***audit_logs,
    path &base_path,
    path &out_path)
{
  int c, n;
  char *pch;
  list<path*> aulogs;
  path out_path_;

  while ((c = getopt(argc, argv, "a:b:o:")) != -1)
  {
    switch (c)
    {
      case 'a':
        pch = strtok(optarg, ",");
        while (pch != NULL)
        {
          aulogs.push_back(new path(pch));
          pch = strtok(NULL, ",");
        }
        break;

      case 'b': base_path = optarg; break;
      case 'o': out_path_ = optarg; break;
      case '?':
        if (optopt == 'b' || optopt == 'a')
          fprintf(stderr, "Option -%c requires an argument.\n", optopt);
        if (isprint(optopt))
          fprintf(stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf(stderr, "Unknown option character `\\x%x'.\n",
              optopt);
      default:
        abort();
    }
  }

  //
  // Prepend paths with base_path
  //

  n = 0;
  *audit_logs = new char*[aulogs.size() + 1];
  BOOST_FOREACH(path *p, aulogs)
  {
    path abspath = base_path / *p;
    abspath.normalize();
    (*audit_logs)[n] = new char[abspath.string().size() + 1];
    strcpy( (*audit_logs)[n], abspath.string().c_str());
    delete p;
    n++;
  }
  (*audit_logs)[n] = NULL;

  if (!base_path.empty() && !out_path_.empty())
  {
    out_path = base_path / out_path_;
    out_path.normalize();
  }
}

void freeAuditLogNames(char ** audit_logs)
{
  if (audit_logs)
  {
    int n = 0;
    while (audit_logs[n] != NULL) delete [] audit_logs[n++];
    delete [] audit_logs;
  }
}

void printUsage( char** argv )
{
  printf( "Usage: %s -b <base-path> -a <audit.log.1,audit.log.2,...> -o <out-log>\n", argv[0] );
}

int main(int argc, char** argv)
{
  char** audit_logs = NULL;
  char *out_log = NULL;
  path base_path;
  path out_path;

  printf("Getting arguments...\n");
  getArgs( argc, argv, &audit_logs, base_path, out_path);
  printf("Base path: %s\nOut path: %s\n", base_path.string().c_str(), out_path.string().c_str());
  if (audit_logs == NULL || out_path.empty())
  {
    printUsage( argv );
    return 0;
  }


  //
  // Initializations
  //
  printf("Initializing dedup...\n");
  auparse_state_t *au = auparse_init(AUSOURCE_FILE_ARRAY, (const char**) audit_logs);

  FILE *out_file = fopen( out_path.string().c_str(), "a" );
  if (out_file == NULL)
  {
    fprintf(stderr, "Error opening output file \"%s\"!\n", out_path.string().c_str());
    return -1;
  }

  dd_init();

  //
  // Begin the real work
  //

  int n = 0;
  char line [MAX_AUDIT_MESSAGE_LENGTH];
  while ( ausearch_next_event( au ) > 0 )
  {
    // printf ( "%s", line ); /* write the line */

    int rc = auparse_first_record( au );
    while (rc == 1)
    {
      const char* r = auparse_get_record_text( au );
      struct auditd_reply_list* rep = make_reply_from_line(r);
      dd_fprintf( out_file, rep );
      n++;
      rc = auparse_next_record( au );
    }

    auparse_next_event( au );
  }

  dd_destroy();
  fclose( out_file );
  auparse_destroy( au );
  printf("Processed %d lines\n", n);
}

