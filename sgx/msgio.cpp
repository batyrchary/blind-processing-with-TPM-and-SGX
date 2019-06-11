#ifdef _WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif

# include <WinSock2.h>
# include <WS2tcpip.h>

typedef DWORD ssize_t;
#endif

#pragma warning(disable:4996)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sgx_urts.h>
#ifdef _WIN32
# pragma comment(lib, "Ws2_32.lib")
# pragma comment(lib, "Mswsock.lib")
# pragma comment(lib, "AdvApi32.lib")
#else
# include <arpa/inet.h>
# include <sys/socket.h>
# include <netdb.h>
# include <unistd.h>
#endif
#include <exception>
#include <stdexcept>
#include <string>
#include "hexutil.h"
#include "msgio.h"
#include "common.h"

using namespace std;

static char *buffer = NULL;
static uint32_t buffer_size = MSGIO_BUFFER_SZ;

#ifndef _WIN32
# ifndef INVALID_SOCKET
#  define INVALID_SOCKET -1
# endif
#endif

/* With no arguments, we read/write to stdin/stdout using stdio */

MsgIO::MsgIO()
{
	use_stdio = true;
	s = -1;
	ls = -1;
}

/* Connect to a remote server and port, and use socket IO */

MsgIO::MsgIO(const char *peer, const char *port)
{
#ifdef _WIN32
	WSADATA wsa;
#endif
	int rv, proto;
	struct addrinfo *addrs, *addr, hints;

	use_stdio = false;
#ifdef _WIN32
	rv = WSAStartup(MAKEWORD(2, 2), &wsa);
	if (rv != 0) {
		eprintf("WSAStartup: %d\n", rv);
		throw std::runtime_error("WSAStartup failed");
	}
#endif

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (peer == NULL) hints.ai_flags = AI_PASSIVE; // Server here
	hints.ai_protocol = IPPROTO_TCP;

	rv = getaddrinfo(peer, port, &hints, &addrs);
	if (rv != 0) {
		eprintf("getaddrinfo: %s\n", gai_strerror(rv));
		throw std::runtime_error("getaddrinfo failed");
	}

	for (addr = addrs; addr != NULL; addr = addr->ai_next)
	{
		proto = addr->ai_family;
		s = socket(addr->ai_family, addr->ai_socktype,
			addr->ai_protocol);
		if (s == -1) {
			perror("socket");
			continue;
		}

		if (peer == NULL) { 	// We're the server
			int enable = 1;

			setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&enable, sizeof(enable));
#ifdef SO_REUSEPORT
			setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable));
#endif
#ifdef IPV6_V6ONLY
			// If we have an IPV6 socket, make sure it will accept IPv4 connections, too
			if (addr->ai_family == AF_INET6) {
				int disable = 0;
				setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&disable, sizeof(disable));
			}
#endif

			if (bind(s, addr->ai_addr, (int)addr->ai_addrlen) == 0) break;
		}
		else {	// We're the client
			if (connect(s, addr->ai_addr, (int)addr->ai_addrlen) == 0) break;
		}

#ifdef _WIN32
		closesocket(s);
#else
		close(s);
#endif
		s = INVALID_SOCKET;
	}

	freeaddrinfo(addrs);

	if (s == INVALID_SOCKET) {
		if (peer == NULL) {
#ifdef _WIN32
			eprintf("bind: failed on error %ld\n", WSAGetLastError());
#else
			perror("bind");
#endif
		}
		else {
			eprintf("%s: ", peer);
#ifdef _WIN32
			eprintf("connect: failed on error %ld\n", WSAGetLastError());
#else
			perror("connect");
#endif
		}
		throw std::runtime_error("could not establish socket");
	}

	if (peer == NULL) {	// Server here. Create our listening socket.
		int enable = 1;
		ls = s;				// Use 'ls' to refer to the listening socket
		s = INVALID_SOCKET;	// and 's' as the session socket.

		if (listen(ls, 5) == -1) { // The "traditional" backlog value in UNIX
			perror("listen");
#ifdef _WIN32
			closesocket(ls);
#else
			close(ls);
#endif
			throw std::runtime_error("could not listen on socket");
		}

		// We have a very simple server: it will block until we get a 
		// connection.

		eprintf("Listening for connections on port %s\n", port);
	}
	else { // Client here




	}
}

MsgIO::~MsgIO()
{
	// Shutdown our socket(s)
	if (s != -1) {
#ifdef _WIN32
		shutdown(s, 2);
		closesocket(s);
#else
		shutdown(s, SHUT_RDWR);
		close(s);
#endif
	}

	if (ls != -1) {
#ifdef _WIN32
		shutdown(ls, 2);
		closesocket(ls);
#else
		shutdown(ls, SHUT_RDWR);
		close(ls);
#endif
	}
}


int MsgIO::server_loop()
{
	int proto;
	struct sockaddr_in6 cliaddr; // Large enough for an IP4 or IP6 peer
	socklen_t slen = sizeof(struct sockaddr_in6);

	if (use_stdio) return 1;

	// This will block until we get a client.

	printf("Waiting for a client to connect...\n");
	fflush(stdout);

	s = accept(ls, (sockaddr *)&cliaddr, &slen);
	if (s == INVALID_SOCKET) {
#ifdef _WIN32
		closesocket(ls);
		eprintf("accept: %d\n", WSAGetLastError());
#else
		close(ls);
		perror("accept");
#endif
		return 0;
	}

	proto = cliaddr.sin6_family;

	eprintf("Connection from ");

	// A client has connected.

	if (proto == AF_INET) {
		char clihost[INET_ADDRSTRLEN];
		sockaddr_in *sa = (sockaddr_in *)&cliaddr;

		memset(clihost, 0, sizeof(clihost));

		if (inet_ntop(proto, &sa->sin_addr, clihost,
			sizeof(clihost)) != NULL) {

			eprintf("%s", clihost);
		}
		else eprintf("(could not translate network address)");
	}
	else if (proto == AF_INET6) {
		char clihost[INET6_ADDRSTRLEN];

		memset(clihost, 0, sizeof(clihost));

		if (inet_ntop(proto, &cliaddr.sin6_addr, clihost,
			sizeof(clihost)) != NULL) {

			eprintf("%s", clihost);
		}
		else eprintf("(could not translate network address)");
	}
	eprintf("\n");

	return 1;
}

void MsgIO::disconnect()
{
	if (use_stdio) return;

	if (s != -1) {
#ifdef _WIN32
		shutdown(s, 2);
		closesocket(s);
#else
		shutdown(s, SHUT_RDWR);
		close(s);
#endif
	}
}


int MsgIO::myRead(char* recvbuf, int *sz)
{
	int recvbuflen = 512;

	int iResult = recv(s, recvbuf, recvbuflen, NULL);

	*sz = iResult;
	return 0;
}

int MsgIO::mySend(char *src, size_t *sz)
{
	wbuffer.append(src);

	size_t  len = wbuffer.length();

	ssize_t bsent = ::send(s, src, (int)len, 0);
	wbuffer.erase(0, bsent);

	return 0;
}




int MsgIO::ReadStruct(message *rec)
{
	int size;  //no need to initialize
	recv(s, (char *)&size, sizeof(int), 0);

	//cout << std::dec;
	//cout << "sizeOfMesssageReceived1=" << size << endl;

	int tobeReceived = size;
	char* buffer = (char *)malloc(tobeReceived);

	while (size > 0)
	{
		int iResult = recv(s, (char*)&buffer[tobeReceived - size], size, NULL);
		size = size - iResult;
	}

	//unsigned char* charPtr = (unsigned char*)buffer;
	//cout << "data=>" << endl;
	//for (int i = 0; i < tobeReceived; i++)
	//	printf("%02x ", charPtr[i]);

	//cout << endl;

	deserialize(buffer, rec, tobeReceived);

	return 0;
}

void MsgIO::printMessage(message *dest, int i_o)
{
	if (i_o == 1)
	{
		cout << "-----------smessage------------" << endl;
	}
	else
	{
		cout << "-----------rmessage------------" << endl;
	}

	printf("command=%d\n", dest->command);
	printf("range=%d-%d\n", dest->startPCR, dest->endPCR);

	cout << endl << "RestInStruct=>" << endl;
	for (auto val : dest->Rest) printf("\\x%.2x", val);
	cout << endl;
}

int MsgIO::SendStruct(message *sen)
{
	int totalSize = 3 * sizeof(int) + (sen->Rest.size()) * sizeof(sen->Rest[0]);
	char *data = (char*) malloc(totalSize);
	serialize(sen, data);
	
	int size = totalSize;
	int sizeUpper = totalSize;
	int bsent = ::send(s, (char *)&sizeUpper, sizeof(int), 0);
	while (size > 0)
	{
		bsent = ::send(s, ((char*)data) + (sizeUpper - size), size, 0);
		size = size - bsent;
	}
	
	//unsigned char* charPtr = (unsigned char*)data;
	//cout << "data=>" << endl;
	//for (int i = 0; i < totalSize; i++)
	//	printf("%02x ", charPtr[i]);
	//cout << endl;

	return 0;
}


void MsgIO::serialize(message* msgPacket, char *data)
{
	int *q = (int*)data;
	*q = msgPacket->command;       q++;
	*q = msgPacket->startPCR;   q++;
	*q = msgPacket->endPCR;     q++;

	BYTE *p = (BYTE*)q;
	int i = 0;
	while (i < msgPacket->Rest.size())
	{
		*p = msgPacket->Rest[i];
		p++;
		i++;
	}
}

void MsgIO::deserialize(char *data, message* msgPacket, int size)
{
	int *q = (int*)data;
	msgPacket->command = *q;       q++;
	msgPacket->startPCR = *q;   q++;
	msgPacket->endPCR = *q;     q++;

	int leftSize = size - 3 * sizeof(int);

	BYTE *p = (BYTE*)q;
	int i = 0;
	while (i < leftSize)
	{
		msgPacket->Rest.push_back(*p);
		p++;
		i++;
	}
}









int MsgIO::read(void **dest, size_t *sz)
{
	ssize_t bread = 0;
	bool repeat = true;
	int ws;

	if (use_stdio) return read_msg(dest, sz);


	//  We don't know how many bytes are coming, so read until we find a newline.


	if (sz) *sz = 0;

	while (repeat) {
	again:
		bread = recv(s, lbuffer, sizeof(lbuffer), 0);
		
		if (bread == -1) {
			if (errno == EINTR) goto again;
			perror("recv");
			return -1;
		}
		if (bread > 0) {
			size_t idx;

			if (debug) eprintf("+++ read %ld bytes from socket\n", bread);
			rbuffer.append(lbuffer, bread);
			idx = rbuffer.find("\r\n");
			if (idx == string::npos) {
				idx = rbuffer.find('\n');
				if (idx == string::npos) continue;
				ws = 1;
			}
			else ws = 2;

			if (idx == 0) return 1;
			else if (idx % 2) {
				eprintf("read odd byte count %zu\n", idx);
				return 0;
			}
			if (sz != NULL) *sz = idx;

			*dest = (char *)malloc(idx / 2);
			if (*dest == NULL) {
				perror("malloc");
				return -1;
			}

			if (debug) {
				edividerWithText("read buffer");
				fwrite(rbuffer.c_str(), 1, idx, stdout);
				printf("\n");
				edivider();
			}

			from_hexstring((unsigned char *)*dest, rbuffer.c_str(), idx / 2);
			rbuffer.erase(0, idx + ws);

			return 1;
		}
		else return 0;
	}

	return -1;
}

void MsgIO::send(void *src, size_t sz)
{
	ssize_t bsent;
	size_t len;

	if (use_stdio) {
		send_msg(src, sz);
		return;
	}

	wbuffer.append(hexstring(src, sz));
	wbuffer.append("\n");

	while (len = wbuffer.length()) {
	again:
		bsent = ::send(s, wbuffer.c_str(), (int)len, 0);
		if (bsent == -1) {
			if (errno == EINTR) goto again;
			perror("send");
			return;
		}
		fwrite(wbuffer.c_str(), 1, bsent, stdout);

		if (bsent == len) {
			wbuffer.clear();
			return;
		}

		wbuffer.erase(0, bsent);
	}
}

void MsgIO::send_partial(void *src, size_t sz)
{
	if (use_stdio) {
		send_msg_partial(src, sz);
		return;
	}

	wbuffer.append(hexstring(src, sz));
}

/*
* Read a msg from stdin. There's a fixed portion and a variable-length
* payload.
*
* Our destination buffer is the entire message plus the payload,
* returned to the caller. This lets them cast it as an sgx_ra_msgN_t
* structure, and take advantage of the flexible array member at the
* end (if it has one, as sgx_ra_msg2_t and sgx_ra_msg3_t do).
*
* All messages are base16 encoded (ASCII hex strings) for simplicity
* and readability. We decode the message into the destination.
*
* We do not allow any whitespace in the incoming message, save for the
* terminating newline.
*
*/


/* Note that these were written back when this was pure C */

int read_msg(void **dest, size_t *sz)
{
	size_t bread;
	int repeat = 1;

	if (buffer == NULL) {
		buffer = (char *)malloc(buffer_size);
		if (buffer == NULL) {
			perror("malloc");
			return -1;
		}
	}

	bread = 0;
	while (repeat) {
		if (fgets(&buffer[bread], (int)(buffer_size - bread), stdin) == NULL) {
			if (ferror(stdin)) {
				perror("fgets");
				return -1;
			}
			else {
				fprintf(stderr, "EOF received\n");
				return 0;
			}
		}
		/* If the last char is not a newline, we have more reading to do */

		bread = strlen(buffer);
		if (bread == 0) {
			fprintf(stderr, "EOF received\n");
			return 0;
		}

		if (buffer[bread - 1] == '\n') {
			repeat = 0;
			--bread;	/* Discard the newline */
		}
		else {
			buffer_size += MSGIO_BUFFER_SZ;
			buffer = (char *)realloc(buffer, buffer_size);
			if (buffer == NULL) return -1;
		}
	}

	/* Make sure we didn't get \r\n */
	if (bread && buffer[bread - 1] == '\r') --bread;

	if (bread % 2) {
		fprintf(stderr, "read odd byte count %zu\n", bread);
		return 0;	/* base16 encoding = even number of bytes */
	}

	*dest = malloc(bread / 2);
	if (*dest == NULL) return -1;

	if (debug) {
		edividerWithText("read buffer");
		eputs(buffer);
		edivider();
	}

	from_hexstring((unsigned char *)*dest, buffer, bread / 2);

	if (sz != NULL) *sz = bread;

	return 1;
}

/* Send a partial message (no newline) */

void send_msg_partial(void *src, size_t sz) {
	if (sz) print_hexstring(stdout, src, sz);
#ifndef _WIN32
	/*
	* If were aren't writing to a tty, also print the message to stderr
	* so you can still see the output.
	*/
	if (!isatty(fileno(stdout))) print_hexstring(stderr, src, sz);
#endif
}

void send_msg(void *src, size_t sz)
{
	if (sz) print_hexstring(stdout, src, sz);
	printf("\n");
#ifndef _WIN32
	/* As above */
	if (!isatty(fileno(stdout))) {
		print_hexstring(stderr, src, sz);
		fprintf(stderr, "\n");
	}
#endif

	/*
	* Since we have both stdout and stderr, flush stdout to keep the
	* the output stream synchronized.
	*/

	fflush(stdout);
}


/* Send a partial message (no newline) */

void fsend_msg_partial(FILE *fp, void *src, size_t sz) {
	if (sz) print_hexstring(fp, src, sz);
}

void fsend_msg(FILE *fp, void *src, size_t sz)
{
	if (sz) print_hexstring(fp, src, sz);
	fprintf(fp, "\n");
	fflush(fp);
}

