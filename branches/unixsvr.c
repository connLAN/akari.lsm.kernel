#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
	if (fork() == 0) {
		struct sockaddr_un addr = { };
		int fd = socket(PF_UNIX, SOCK_STREAM, 0);
		addr.sun_family = AF_UNIX;
		snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1,  "/stream");
		if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) ||
		    listen(fd, 5))
			_exit(1);
		while (close(accept(fd, NULL, 0)) == 0);
		_exit(1);
	}
	if (fork() == 0) {
		struct sockaddr_un addr = { };
		int fd = socket(PF_UNIX, SOCK_DGRAM, 0);
		char c;
		addr.sun_family = AF_UNIX;
		snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1,  "/dgram");
		if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)))
			_exit(1);
		while (read(fd, &c, 1) == 1);
		_exit(1);
	}
	if (fork() == 0) {
		struct sockaddr_un addr = { };
		int fd = socket(PF_UNIX, SOCK_SEQPACKET, 0);
		addr.sun_family = AF_UNIX;
		snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1,  "/seqpacket");
		if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) ||
		    listen(fd, 5))
			_exit(1);
		while (close(accept(fd, NULL, 0)) == 0);
		_exit(1);
	}
	while (wait(NULL) != EOF);
	return 0;
}
