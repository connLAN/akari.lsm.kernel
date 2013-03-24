#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char *argv[])
{
	struct sockaddr_un addr;
	int fd = socket(PF_UNIX, SOCK_STREAM, 0);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1,  "/stream");
	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr))) {
		const int err = errno; 
		fprintf(stderr, "stream_connect=%s\n", strerror(err));
	} else {
		fprintf(stderr, "stream_connect=success\n");
	}
	close(fd);
	fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1,  "/dgram");
	if (sendto(fd, "",  1, 0, (struct sockaddr *) &addr, sizeof(addr)) == EOF) {
		const int err = errno; 
		fprintf(stderr, "dgram_sendto=%s\n", strerror(err));
	} else {
		fprintf(stderr, "dgram_sendto=success\n");
	}
	close(fd);
	fd = socket(PF_UNIX, SOCK_DGRAM, 0);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1,  "/dgram");
	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr))) {
		const int err = errno; 
		fprintf(stderr, "dgram_connect=%s\n", strerror(err));
	} else {
		fprintf(stderr, "dgram_connect=success\n");
	}
	close(fd);
	fd = socket(PF_UNIX, SOCK_SEQPACKET, 0);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1,  "/seqpacket");
	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr))) {
		const int err = errno; 
		fprintf(stderr, "seqpacket_connect=%s\n", strerror(err));
	} else {
		fprintf(stderr, "seqpacket_connect=success\n");
	}
	close(fd);
	return 0;
}
