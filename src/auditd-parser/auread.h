#ifndef __AUREAD_HEADER__
#define __AUREAD_HEADER__

#include <sys/stat.h>
#include <stdio.h>
#include <list>
#include <string>
#include <libaudit.h>
//#include "fsbuf.h"

#define POOL_RECORD_SIZE  10
#define POOL_FIELD_SIZE   512
#define MAX_STR_LEN       16384

typedef unsigned long serial_t;
typedef unsigned int  milli_t;

typedef struct
{
  time_t sec;        // Event seconds
  milli_t milli;     // millisecond of the timestamp
  serial_t serial;   // Serial number of the event
} au_event_t; // adapted from auparse-defs.h

typedef struct
{
  //FSBuf *name;
  //FSBuf *str;
  std::string name;
  std::string str;
} AUREAD_FIELD;

typedef struct
{
  int                       type;
  au_event_t                timestamp;
  std::list<AUREAD_FIELD*>  fields;
} AUREAD_RECORD;

typedef struct
{
  au_event_t                timestamp;
  std::list<AUREAD_RECORD*> records;
} AUREAD_EVENT;

class AuRead; // forward declaration
typedef enum {AUPARSE_CB_EVENT_READY} auparse_cb_event_t; // from auparse-defs.h
typedef void (*auread_callback_ptr)(AuRead *au, auparse_cb_event_t cb_event_type, void *ptr);
typedef void (*auread_user_destroy)(void *user_data);

class AuRead
{
  public:
    AuRead(const char **filenames);
    ~AuRead();
    int               nextEvent();
    int               getType();
    int               firstRecord();
    int               firstField();
    int               nextRecord();
    int               nextField();
    const char       *getFieldName();
    const char       *getFieldStr();
    int               getFieldInt();
    const au_event_t *getTimestamp();

		serial_t					getSerial();
		unsigned int			getNumRecords();
		const char			 *getRecordText();

    int feed(const char *data, size_t data_len);
    int flushFeed();
    void addCallback(
        auread_callback_ptr callback,
        void *user_data,
        auread_user_destroy user_destroy);

  private:
    int                       nf_;
    struct stat               fstat_;     // file stat
    int                       fd_;        // file descriptor
    char                      *fp_;       // mmap pointer
    size_t                    cb_;        // bytes read
    const char                **fnames_;
    AUREAD_EVENT              *curr_event_;
    AUREAD_EVENT              *next_event_;
    std::list<AUREAD_RECORD*> pool_records_; // pool of records
    std::list<AUREAD_FIELD*>  pool_fields_;  // pool of fields
    std::list<AUREAD_RECORD*>::iterator record_itr_;
    std::list<AUREAD_FIELD*>::iterator  field_itr_;
    auread_callback_ptr       callback_;
    auread_user_destroy       user_destroy_;
    void                      *user_data_;
    std::string               feed_buf_;
		std::string								curr_record_text_;
    /*
    FSPool                    *fspool4_;
    FSPool                    *fspool16_;
    FSPool                    *fspool64_;
    FSPool                    *fspool256_;
    FSPool                    *fspool1024_;
    FSPool                    *fspool4096_;
    FSPool                    *fspool16384_;
    */

    int chompBuf(char *buf);

    static void freeEvent(AUREAD_EVENT *event);
    static void freeRecord(AUREAD_RECORD *rec);

    //FSBuf *getFSBuf(size_t req);

    int readEventFromFile();
    serial_t parseRecord(AUREAD_RECORD &rec, char *buf);
    static void parseTimestamp(char *timestr, au_event_t &timetamp);
    static inline int first_atoi(const char *buf);
};

#define auparse_state_t                         AuRead
#define auparse_init(src, audit_logs)           new AuRead(audit_logs)
#define auparse_add_callback(au, cb, ptr, free) au->addCallback(cb, ptr, free)
#define auparse_feed(au, data, len)             au->feed(data, len)
#define auparse_flush_feed(au)                  au->flushFeed()
#define ausearch_set_stop(au, AUSEARCH)         false
#define ausearch_add_item(au,s1,s2,s3,r)        false
#define auparse_get_type(au)                    au->getType()
#define auparse_next_event(au)
#define ausearch_next_event(au)                 au->nextEvent()
#define auparse_first_record(au)                au->firstRecord()
#define auparse_next_record(au)                 au->nextRecord()
#define auparse_get_num_records(au)							au->getNumRecords()
#define auparse_get_serial(au)									au->getSerial()
#define auparse_get_record_text(au)							au->getRecordText()
#define auparse_first_field(au)                 au->firstField()
#define auparse_next_field(au)                  au->nextField()
#define auparse_get_field_int(au)               au->getFieldInt()
#define auparse_get_field_name(au)              au->getFieldName()
#define auparse_get_field_str(au)               au->getFieldStr()
#define auparse_get_timestamp(au)								au->getTimestamp()
#define auparse_destroy(au)               	  	delete au

#endif
