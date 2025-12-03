#pragma once
#include "stdafx.h"
#include "stdio.h"
#include "string.h"

#ifdef __cplusplus
extern "C"
{
#endif
	void rc4_set_key(unsigned char* rc_key, unsigned char* key, int keylen);
	void rc4_transform(unsigned char* rc_key, unsigned char* input, int len);
	void asc_hex(unsigned char* asc_buf, unsigned char* hex_buf, unsigned int length);
	void hex_asc(unsigned char* hex_buf, unsigned char* asc_buf, unsigned short length);
#ifdef __cplusplus
}
#endif