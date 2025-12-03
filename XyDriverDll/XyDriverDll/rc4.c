#include "rc4.h"

void rc4_set_key(unsigned char* rc_key, unsigned char* key, int keylen)
{
	int i = 0, j = 0;
	unsigned char tmp;
	for (i = 0; i < 256; i++)
	{
		rc_key[i] = i;
	}
	for (i = 0; i < 256; i++)
	{
		j = (j + rc_key[i] + key[i % keylen]) % 256;
		tmp = rc_key[i];
		rc_key[i] = rc_key[j];
		rc_key[j] = tmp;
	}
}

void rc4_transform(unsigned char* rc_key, unsigned char* input, int len)
{
	int i = 0, j = 0, k = 0;
	char tmp;
	unsigned char subkey;
	for (k = 0; k < len; k++)
	{
		i = (i + 1) % 256;
		j = (j + rc_key[i]) % 256;

		tmp = rc_key[i];
		rc_key[i] = rc_key[j];
		rc_key[j] = tmp;
		subkey = rc_key[(rc_key[i] + rc_key[j]) % 256];
		input[k] ^= subkey;
	}
}
//ASCII码转换为16进制  
void asc_hex(unsigned char* asc_buf, unsigned char* hex_buf, unsigned int length)
{
	int i, j;
	for (i = 0, j = 0; i < length; i++)
	{
		if (asc_buf[i] > '9')
		{
			hex_buf[j] = 9 + (asc_buf[i] & 0x0F);
		}
		else
		{
			hex_buf[j] = asc_buf[i] & 0x0F;
		}

		hex_buf[j] <<= 4;
		i++;
		if (asc_buf[i] > '9')
		{
			hex_buf[j] |= 9 + (asc_buf[i] & 0x0F);
		}
		else
		{
			hex_buf[j] |= asc_buf[i] & 0x0F;
		}
		j++;
	}
}
//16进制转换为ASCII码
void hex_asc(unsigned char* hex_buf, unsigned char* asc_buf, unsigned short length)
{
	unsigned short i;
	unsigned char byte;
	for (i = 0; i < length; i++)
	{
		byte = hex_buf[i] >> 4;
		if (byte > 9)
		{
			asc_buf[i * 2] = 'A' + byte - 10;
		}
		else
		{
			asc_buf[i * 2] = '0' + byte;
		}

		byte = hex_buf[i] & 0x0F;
		if (byte > 9)
		{
			asc_buf[i * 2 + 1] = 'A' + byte - 10;
		}
		else
		{
			asc_buf[i * 2 + 1] = '0' + byte;
		}
	}
}