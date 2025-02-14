
/*
	Imported by Evilnat for xai_plugin from flatz's EID root key dumper
*/

#ifndef _PAYLOAD_H_
#define _PAYLOAD_H_

extern uint64_t toc;

void lv2_copy_from_user(const void* src, uint64_t dst, uint64_t size);
int install_payload(void);
int remove_payload(void);

#endif
