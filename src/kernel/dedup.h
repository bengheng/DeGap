#ifndef __DEDUP_HEADER__
#define __DEDUP_HEADER__

#ifndef __KERNEL__
#include <stdio.h>
#include <libaudit.h>

typedef void (*ack_func_type)(void *ack_data, const unsigned char *header, const char *msg);

struct auditd_reply_list {
	struct audit_reply reply;
	struct auditd_reply_list *next;
	ack_func_type ack_func;
	void *ack_data;
	unsigned long sequence_id;
};

void dd_printf (const char * format, ...);
int dd_fprintf( FILE* log_file, struct auditd_reply_list* rep );
#endif // NOT __KERNEL__

void dd_init();
void dd_destroy();

#endif
