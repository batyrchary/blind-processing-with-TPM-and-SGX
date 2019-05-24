#ifndef __MSGIO_H
#define __MSGIO_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <sys/types.h>
#include <sgx_urts.h>
#include <stdio.h>
#ifdef _WIN32
#include <WS2tcpip.h>
#endif
#include <string>
#include <iostream>
#include <vector>
using namespace std;

#define STRUCT_INCLUDES_PSIZE	0
#define STRUCT_OMITS_PSIZE		1


#define MSGIO_BUFFER_SZ	1024*1024

#define DEFAULT_PORT	"7777"		// A C string for getaddrinfo()

#ifndef _WIN32
typedef int SOCKET;
#endif


struct message {
	int command = 0;
	int startPCR = 0;
	int endPCR = 0;
	char Nonce[10] = {'\0'}; //10byte
	char result[60] = { '\0' };
};


class MsgIO {
	string wbuffer, rbuffer;
	char lbuffer[MSGIO_BUFFER_SZ];
	bool use_stdio;
	SOCKET ls, s;

public:
	MsgIO();
	MsgIO(const char *server, const char *port);
	~MsgIO();

	int server_loop();
	void disconnect();

	int read(void **dest, size_t *sz);

	void send_partial(void *buf, size_t f_size);
	void send(void *buf, size_t f_size);

	int myRead(char *dest, int *sz);
	int mySend(char *dest, size_t *sz);

	int SendStruct(message *dest);
	int ReadStruct(message *dest);

	void printMessage(message *dest, int i_o);

};

#ifdef __cplusplus
extern "C" {
#endif

extern char debug;
extern char verbose;

int read_msg(void **dest, size_t *sz);

void send_msg_partial(void *buf, size_t f_size);
void send_msg(void *buf, size_t f_size);

void fsend_msg_partial(FILE *fp, void *buf, size_t f_size);
void fsend_msg(FILE *fp, void *buf, size_t f_size);

#ifdef __cplusplus
};
#endif


#endif
