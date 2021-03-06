/* des_read.c */
/* Copyright (C) 1992 Eric Young - see COPYING for more details */
#include <errno.h>
#include "des_local.h"

/* This has some uglies in it but it works - even over sockets. */
extern int errno;
int des_rw_mode=DES_PCBC_MODE;

/* Functions to convert from/to network byte order (big endian)
 * for MSDOS (little endian) */
#ifdef MSDOS
#define NETCONV(name) \
ulong name(l) \
ulong l; \
	{ \
	ulong t; \
\
	t=(l>>16)|(l<<16); \
	t=((t<<8)&0xff00ff00)|((t>>8)&0x00ff00ff); \
	return(t); \
	}

NETCONV(htonl);
NETCONV(ntohl);
#endif


int des_enc_read(fd,buf,len,sched,iv)
int fd;
char *buf;
int len;
des_key_schedule sched;
des_cblock *iv;
	{
	/* data to be unencrypted */
	int net_num=0;
	char net[BSIZE];
	/* extra unencrypted data 
	 * for when a block of 100 comes in but is des_read one byte at
	 * a time. */
	static char unnet[BSIZE];
	static int unnet_start=0;
	static int unnet_left=0;
	int i;
	long num=0,rnum;

	/* left over data from last decrypt */
	if (unnet_left != 0)
		{
		if (unnet_left < len)
			{
			/* we still still need more data but will return
			 * with the number of bytes we have - should always
			 * check the return value */
			bcopy(&(unnet[unnet_start]),buf,unnet_left);
			unnet_start=unnet_left=0;
			i=unnet_left;
			}
		else
			{
			bcopy(&(unnet[unnet_start]),buf,len);
			unnet_start+=len;
			unnet_left-=len;
			i=len;
			}
		return(i);
		}

	/* We need to get more data. */
	if (len > MAXWRITE) len=MAXWRITE;

	/* first - get the length */
	net_num=0;
	while (net_num < sizeof(long)) 
		{
		i=read(fd,&(net[net_num]),sizeof(long)-net_num);
		if ((i == -1) && (errno == EINTR)) continue;
		if (i <= 0) return(0);
		net_num+=i;
		}

	/* we now have at net_num bytes in net */
	bcopy(&(net[0]),&num,sizeof(long));
	num=ntohl(num);
	/* num should be rounded up to the next group of eight
	 * we make sure that we have read a multiple of 8 bytes from the net.
	 */
	rnum=(num < 8)?8:((num+7)/8*8);
	net_num=0;
	while (net_num < rnum)
		{
		i=read(fd,&(net[net_num]),rnum-net_num);
		if ((i == -1) && (errno == EINTR)) continue;
		if (i <= 0) return(0);
		net_num+=i;
		}

	/* Check if there will be data left over. */
	if (len < num)
		{
		if (des_rw_mode == DES_PCBC_MODE)
			pcbc_encrypt((des_cblock *)net,(des_cblock *)unnet,
				num,sched,iv,DES_DECRYPT);
		else
			cbc_encrypt((des_cblock *)net,(des_cblock *)unnet,
				num,sched,iv,DES_DECRYPT);
		bcopy(unnet,buf,len);
		unnet_start=len;
		unnet_left=num-len;

		/* The following line is done because we return num
		 * as the number of bytes read. */
		num=len;
		}
	else
		{
		/* >output is a multiple of 8 byes, if len < rnum
		 * >we must be careful.  The user must be aware that this
		 * >routine will write more bytes than he asked for.
		 * >The length of the buffer must be correct.
		 * FIXED - Should be ok now 18-9-90 - eay */
		if (len < rnum)
			{
			char tmpbuf[BSIZE];

			if (des_rw_mode == DES_PCBC_MODE)
				pcbc_encrypt((des_cblock *)net,
					(des_cblock *)tmpbuf,
					num,sched,iv,DES_DECRYPT);
			else
				cbc_encrypt((des_cblock *)net,
					(des_cblock *)tmpbuf,
					num,sched,iv,DES_DECRYPT);

			bcopy(tmpbuf,buf,len);
			}
		else
			{
			if (des_rw_mode == DES_PCBC_MODE)
				pcbc_encrypt((des_cblock *)net,
					(des_cblock *)buf,num,sched,iv,
					DES_DECRYPT);
			else
				cbc_encrypt((des_cblock *)net,
					(des_cblock *)buf,num,sched,iv,
					DES_DECRYPT);
			}
		}
	return(num);
	}

