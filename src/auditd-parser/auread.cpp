#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <boost/foreach.hpp>
#include <boost/tokenizer.hpp>
#include <pthread.h>
#include <assert.h>
#include <string>
#include "auread.h"

using namespace std;

AuRead::AuRead(const char **fnames)
{
  fnames_ = fnames;
  nf_     = 0;
  fd_     = -1;
  fp_     = (char*) MAP_FAILED;
  cb_     = 0;

  // Allocate events
  curr_event_ = new AUREAD_EVENT();
  curr_event_->timestamp.serial  = 0;
  curr_event_->timestamp.sec     = 0;
  curr_event_->timestamp.milli   = 0;

  next_event_ = new AUREAD_EVENT();
  next_event_->timestamp.serial  = 0;
  next_event_->timestamp.sec     = 0;
  next_event_->timestamp.milli   = 0;

  //
  // Allocate pools
  //
  int i;
  for (i = 0; i < POOL_FIELD_SIZE; ++i)
  {
    AUREAD_FIELD *field = new AUREAD_FIELD();
    pool_fields_.push_back(field);
  }
  for (i = 0; i < POOL_RECORD_SIZE; ++i)
  { pool_records_.push_back(new AUREAD_RECORD()); }

  callback_       = NULL;
  user_destroy_   = NULL;
  user_data_      = NULL;
}


AuRead::~AuRead()
{
  freeEvent(curr_event_);
  freeEvent(next_event_);

  BOOST_FOREACH(AUREAD_RECORD *r, pool_records_)
  { freeRecord(r); }

  BOOST_FOREACH(AUREAD_FIELD *r, pool_fields_)
  { delete r; }
}

//-------------------------------------------------------------------

/*!
 * Free event.
 * */
void AuRead::freeEvent(AUREAD_EVENT *event)
{
  BOOST_FOREACH(AUREAD_RECORD *r, event->records)
  { freeRecord(r); }
  delete event;
}

/*!
 * Free record.
 * */
void AuRead::freeRecord(AUREAD_RECORD *rec)
{
  BOOST_FOREACH(AUREAD_FIELD *f, rec->fields) {
    delete f;
  }
  delete rec;
}

//-------------------------------------------------------------------

int AuRead::nextEvent()
{
  //if (fnames_[nf_] == NULL && fp_ == (char*) MAP_FAILED)
  //  return -1;

  while (fnames_[nf_] != NULL || fp_ != (char*) MAP_FAILED)
  {
    if (fp_ == (char*) MAP_FAILED)
    {
      fprintf(stderr, "DEBUG opening \"%s\"\n", fnames_[nf_]);
      fd_ = open(fnames_[nf_++], O_RDONLY);
      if (fd_ == -1) { perror("open"); return -1; }

      if (fstat(fd_, &fstat_) == -1) { perror("fstat"); return -1; }

      if (!S_ISREG(fstat_.st_mode)) {
        fprintf(stderr, "%s is not a file\n", fnames_[nf_ - 1]);
        return -1;
      }

      fp_ = (char*) mmap(0, fstat_.st_size, PROT_READ, MAP_SHARED, fd_, 0);
      if (fp_ == MAP_FAILED) { perror("mmap"); return -1; }
      cb_ = 0;

      if (close(fd_) == -1) { perror("close"); return -1; }
      fd_ = -1;
    }

    if (readEventFromFile() == 0) return 1;

    if (munmap(fp_, fstat_.st_size) == -1) { perror("munmap"); return -1; }
    fp_ = (char*) MAP_FAILED;
  }

  return -1;
}

/*!
 * Returns first integer in input string.
 * */
inline int AuRead::first_atoi(const char *buf)
{
  const char *cp = buf;

  // Skip non-numerical characters
  char c = *cp;
  while ( (c != '\0') && (c < '0' || c > '9') )
  { c = *(++cp); continue; }

  // Copy numerical characters to intbuf
  char intbuf[32];
  int offset = 0;
  while ( (c >= '0' && c <= '9') &&
      c != '\0' &&
      offset < sizeof(intbuf))
  {
    intbuf[offset++] = c;
    c = *(++cp);
  }
  return atoi(intbuf);
}

/*!
 * Parses timestamp. timestr may be modified. Caller should save
 * a copy if required.
 * */
void AuRead::parseTimestamp(char *timestr, au_event_t &timestamp)
{
  char *saveptr; 

  // Discard first token
  strtok_r(timestr, "(", &saveptr);
  timestamp.sec = (time_t) atoi(strtok_r(NULL, ".", &saveptr));
  timestamp.milli = (milli_t) atoi(strtok_r(NULL, ":", &saveptr));
  timestamp.serial = (serial_t) atoi(strtok_r(NULL, ")", &saveptr));
}

/*!
 * Returns a suitably sized FSBuf for the required len.
 * */
/*
   FSBuf *AuRead::getFSBuf(size_t req)
   {
   FSBuf *fsbuf = NULL;

   if (req <= 4)     { if ((fsbuf = fspool4_->requestBuf())     != NULL) return fsbuf; }
   if (req <= 16)    { if ((fsbuf = fspool16_->requestBuf())    != NULL) return fsbuf; }
   if (req <= 64)    { if ((fsbuf = fspool64_->requestBuf())    != NULL) return fsbuf; }
   if (req <= 256)   { if ((fsbuf = fspool256_->requestBuf())   != NULL) return fsbuf; }
   if (req <= 1024)  { if ((fsbuf = fspool1024_->requestBuf())  != NULL) return fsbuf; }
   if (req <= 4096)  { if ((fsbuf = fspool4096_->requestBuf())  != NULL) return fsbuf; }
   if (req <= 16384) { if ((fsbuf = fspool16384_->requestBuf()) != NULL) return fsbuf; }

   fprintf(stderr, "FATAL! Out of FSBuf!\n");
   return NULL;
   }
   */

/*!
 * Parses buf and populates rec.
 *
 * Returns the serial for the record.
 *
 * Note that buf can be modified. Caller should save a copy of buf
 * if it requires the original version.
 * */
serial_t AuRead::parseRecord(AUREAD_RECORD &rec, char *buf)
{
  //fprintf(stderr, "%s\n", buf);
  AUREAD_FIELD *field;
  list<AUREAD_FIELD*>::iterator field_itr = rec.fields.begin();

  // Tokenize record into fields
  char *rec_saveptr;
  char *rec_token;
  rec_token = strtok_r(buf, " ", &rec_saveptr);
  while (rec_token != NULL)
  {
    if (field_itr == rec.fields.end())
    { // get field from field pool
      assert(!pool_fields_.empty());
      field = pool_fields_.front();
      pool_fields_.pop_front();
      rec.fields.push_back(field);
      assert(field_itr == rec.fields.end());
      //field_itr = rec.fields.end();
    }
    else
    { field = *(field_itr++); }

    // Tokenize by '=' into name and str
    char *field_saveptr;
    //char *field_token;

    field->name = strtok_r(rec_token, "=", &field_saveptr);

    /*
       if (field->name != NULL) field->name->pool->returnBuf(field->name);
       field->name = getFSBuf(strlen(field_token) + 1);
       assert(field->name != NULL);
       strcpy(field->name->str, field_token);
       */

    field->str = strtok_r(NULL, "=", &field_saveptr);
    /*
       if (field->str != NULL) field->str->pool->returnBuf(field->str);
       field->str = getFSBuf(strlen(field_token) + 1);
       assert(field->str != NULL);
       strcpy(field->str->str, field_token);
       */

    rec_token = strtok_r(NULL, " ", &rec_saveptr);
  }

  // Put unused fields back into pool
  if (field_itr != rec.fields.end())
  {
    pool_fields_.splice(
        pool_fields_.end(),  // at end of pool_fields
        rec.fields,        // from rec.fields
        field_itr,          // beginning at
        rec.fields.end()); // ends at
  }

  field_itr = rec.fields.begin();
  field = *field_itr;

  // Extract type info
  /*
     if (strcmp(field->str->str, "SYSCALL") == 0) rec.type = AUDIT_SYSCALL;
     else if (strcmp(field->str->str, "EXECVE") == 0) rec.type = AUDIT_EXECVE;
     else if (strcmp(field->str->str, "PATH") == 0) rec.type = AUDIT_PATH;
     else if (strcmp(field->str->str, "CWD") == 0) rec.type = AUDIT_CWD;
     */

  rec.type = (field->str.compare("PATH") == 0 ? AUDIT_PATH
      : (field->str.compare("SYSCALL") == 0 ? AUDIT_SYSCALL
        : (field->str.compare("CWD") == 0 ? AUDIT_CWD
          : (field->str.compare("EXECVE") == 0 ? AUDIT_EXECVE : 0))));
  /*
     if (field->str.compare("PATH") == 0) rec.type = AUDIT_PATH;
     else if (field->str.compare("SYSCALL") == 0) rec.type = AUDIT_SYSCALL;
     else if (field->str.compare("CWD") == 0) rec.type = AUDIT_CWD;
     else if (field->str.compare("EXECVE") == 0) rec.type = AUDIT_EXECVE;
     */

  // Extract timestamp info
  //field_itr++;
  field = *(++field_itr);
  //size_t len = field->str.length() + 1;
  char timestr[32];
  //char *timestr = (char*) malloc(len);
  strncpy(timestr, field->str.c_str(), sizeof(timestr));
  parseTimestamp(timestr/*field->str->str*/, rec.timestamp);
  //free(timestr);

  return rec.timestamp.serial;
}

int AuRead::chompBuf(char *buf)
{
  if (strstr(buf, "syscall=2") == NULL &&
      strstr(buf, "syscall=59") == NULL &&
      strstr(buf, "type=EXECVE") == NULL &&
      strstr(buf, "type=CWD") == NULL &&
      strstr(buf, "type=PATH") == NULL)
  {
    //fprintf(stderr, "DEBUG chompBuf Unwanted buffer.\n");
    return 1;
  }

  AUREAD_RECORD *record;

  // get record from record pool
  assert(!pool_records_.empty());
  record = pool_records_.front();
  pool_records_.pop_front();
  //fprintf(stderr, "DEBUG Thread %08x get record from pool. %zu left. For \"%s\".\n",
  //		pthread_self(),
  //		pool_records_.size(),
  //		buf);

  serial_t serial = parseRecord(*record, buf);
  //fprintf(stderr, "DEBUG chompBuf serial %d\n", serial);

  if (!curr_event_->records.empty())
  { // other records exist

    if (curr_event_->timestamp.serial == serial)
    { // same serial
      //fprintf(stderr, "DEBUG chompBuf serial exists.\n");
      curr_event_->records.push_back(record);
    }
    else
    { // overflowed to next event
      //fprintf(stderr, "DEBUG chompBuf Serial mismatch (%d, %d). Transferring record...\n",
      //    curr_event_->timestamp.serial, serial);

      next_event_->records.push_back(record);
      /*
         next_event_->timestamp.serial = record->timestamp.serial;
         next_event_->timestamp.sec    = record->timestamp.sec;
         next_event_->timestamp.milli  = record->timestamp.milli;
         */
      memcpy(&(next_event_->timestamp), &(record->timestamp), sizeof(au_event_t));

      // The number of records must always add up
      /*
         assert((curr_event_->records.size() +
         next_event_->records.size() +
         pool_records_.size())
         == POOL_RECORD_SIZE);
         */
      return 0;
    }
  }
  else
  { // empty records
    //fprintf(stderr, "DEBUG chompBuf empty records.\n");
    curr_event_->records.push_back(record);
    memcpy(&(curr_event_->timestamp), &(record->timestamp), sizeof(au_event_t));
  }

  return 1;
}

/*!
 * Reads an event from file.
 *
 * In terms of implementation, we continuously read each line of the file
 * until the serial changes.
 * */
int AuRead::readEventFromFile()
{
  char buf[16384]; // there are some really long entries!

  // If next event contains records, swap it to become current event
  if (!next_event_->records.empty())
  {
    // Transfer all records in curr_event_ back to pool
    pool_records_.splice(
        pool_records_.end(),
        curr_event_->records,
        curr_event_->records.begin(),
        curr_event_->records.end());

    // Swap events
    AUREAD_EVENT *tmp_event = curr_event_;
    curr_event_ = next_event_;
    next_event_ = tmp_event;

    //fprintf(stderr, "next_event_.nrecs %d Copying...\n", next_event_.nrecs);
  }

  //fprintf(stderr, "DEBUG REFF 1 fstat_.st_size %d cb_ %d\n", fstat_.st_size, cb_);

  while (cb_ < fstat_.st_size)
  {
    // fprintf(stderr, "DEBUG REFF 2 fstat_.st_size %d cb_ %d\n", fstat_.st_size, cb_);

    size_t offset = 0;

    size_t nbytes = min(fstat_.st_size - cb_, sizeof(buf));
    char *a = &fp_[cb_];
    char *newline = (char*)memchr(a, '\n', nbytes);
    if (newline != NULL) { nbytes = newline - a + 1; }

    memcpy(buf, a, nbytes);
    buf[nbytes-1] = '\0';
    cb_ += nbytes;

    //fprintf(stderr, "DEBUG REFF (cb_ %d) Chomping \"%s\"\n", cb_, buf);
    if ( chompBuf(buf) == 0 || cb_ == fstat_.st_size )
    {
      //fprintf(stderr, "DEBUG REFF End Chomping curr_event_->timestamp.serial %d\n",
      //    curr_event_->timestamp.serial);

      record_itr_ = curr_event_->records.begin();
      if (!curr_event_->records.empty()) {
        field_itr_ = (*record_itr_)->fields.begin();
      }
      return 0;
    }
  }
  // fprintf(stderr, "DEBUG REFF EOF Chomping \"%s\"\n", buf);

  // If we reach here, means the loop terminated
  // because of failure to read from file.

  record_itr_ = curr_event_->records.begin();
  if (!curr_event_->records.empty()) {
    field_itr_ = (*record_itr_)->fields.begin();
  }

  // The number of records must always add up
  /*
     assert((curr_event_->records.size() +
     next_event_->records.size() +
     pool_records_.size())
     == POOL_RECORD_SIZE);
     */

  return -1;
}
//-------------------------------------------------------------------

int AuRead::getType()
{
  if (record_itr_ == curr_event_->records.end())
    return 0;

  return (*record_itr_)->type;
}

//-------------------------------------------------------------------

int AuRead::firstField()
{
  AUREAD_RECORD *record = *record_itr_;

  if (record->fields.empty())
    return 0;

  field_itr_ = record->fields.begin();
  return 1;
}

int AuRead::nextField()
{
  AUREAD_RECORD *record = *record_itr_;
  if (++field_itr_ == record->fields.end())
    return 0;

  return 1;
}

const char* AuRead::getFieldName()
{
  AUREAD_RECORD *record = *record_itr_;
  if (field_itr_ == record->fields.end())
    return NULL;

  AUREAD_FIELD *field = *field_itr_;
  if (field == NULL) return NULL;

  return field->name.c_str();
}

const char* AuRead::getFieldStr()
{
  AUREAD_RECORD *record = *record_itr_;
  if (field_itr_ == record->fields.end())
    return NULL;

  AUREAD_FIELD *field = *field_itr_;
  if (field == NULL) return NULL;

  return field->str.c_str();
}

int AuRead::getFieldInt()
{
  AUREAD_RECORD *record = *record_itr_;
  if (field_itr_ == record->fields.end())
  { errno = ENOENT; return -1; }

  AUREAD_FIELD *field = *field_itr_;
  if (field == NULL)
  { errno = ENOENT; return -1; }

  return atoi(field->str.c_str());
}

//-------------------------------------------------------------------

int AuRead::firstRecord()
{
  if (curr_event_->records.empty())
    return 0;

  record_itr_ = curr_event_->records.begin();
  return 1;
}

int AuRead::nextRecord()
{
  if (++record_itr_ == curr_event_->records.end())
    return 0;

  return 1;
}

/*!
 * Returns 0 if an error occurs; otherwise, the serial number for the event.
 * */
serial_t AuRead::getSerial()
{
  if (curr_event_->records.empty())
    return 0;

  return curr_event_->timestamp.serial;
}

/*!
 * Returns 0 if an error occurs; otherwise, the number of records.
 * */
unsigned int AuRead::getNumRecords()
{
  return curr_event_->records.size();
}

/*!
 * Returns NULL if an error occurs; otherwise, a pointer to the record.
 * */
const char *AuRead::getRecordText()
{
  curr_record_text_.clear();

  if (record_itr_ == curr_event_->records.end())
    return NULL;

  AUREAD_RECORD *record = *record_itr_;
  if (record == NULL) return NULL;

  BOOST_FOREACH(AUREAD_FIELD* field, record->fields)
  {
    curr_record_text_ += (field->name + "=" + field->str + " ");
  }
  curr_record_text_[ strlen(curr_record_text_.c_str()) - 1 ] = 0x0;
  return curr_record_text_.c_str();
}

//-------------------------------------------------------------------

const au_event_t *AuRead::getTimestamp()
{
  if (curr_event_->records.empty())
    return NULL;

  return &curr_event_->timestamp;
}

//-------------------------------------------------------------------

void AuRead::addCallback(
    auread_callback_ptr callback,
    void *user_data,
    auread_user_destroy user_destroy)
{
  callback_     = callback;
  user_data_    = user_data;
  user_destroy_ = user_destroy;
}

/*!
 * Returns -1 if an error occurs; otherwise, 0 for success.
 * */
int AuRead::feed(const char *data, size_t data_len)
{
  feed_buf_ += data;
  return 0;
}

typedef boost::tokenizer<boost::char_separator<char> > tokenizer;

/*!
 * Returns -1 if an error occurs; otherwise, 0 for success.
 * */
int AuRead::flushFeed()
{
  char buf[16384];

  // Tokenize feed_data by '\n' and process each line
  boost::char_separator<char> sep("\n");
  tokenizer tokens(feed_buf_, sep);
  tokenizer::iterator token_itr = tokens.begin();
  while (token_itr != tokens.end())
  {
    strncpy(buf, token_itr->c_str(), sizeof(buf));
    chompBuf(buf);
    ++token_itr;
  }

  if(callback_ != NULL)
    callback_(this, AUPARSE_CB_EVENT_READY, user_data_);

  if (user_destroy_ != NULL && user_data_ != NULL)
    user_destroy_(user_data_);

  feed_buf_.clear();
  return 0;
}
