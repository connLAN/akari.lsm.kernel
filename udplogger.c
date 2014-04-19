/*
 * Simple UDP logger - A utility for receiving output from netconsole.
 *
 *    Written by Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 *    Distributed under GPL v2.
 */
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <errno.h>
#define round_up(size) ((((size) + 4095u) / 4096u) * 4096u)

/* Structure for holding IPv4 or IPv6 address. */
union ipaddr {
	struct sockaddr_in ip4;
	struct sockaddr_in6 ip6;
};

/* Structure for tracking partially received data. */
static struct client {
	union ipaddr addr; /* Sender's IPv4 or IPv6 address. */
	socklen_t size; /* Valid bytes in @addr . */
	char *buffer; /* Buffer for holding received data. */
	int avail; /* Valid bytes in @buffer . */
	char addr_str[50]; /* String representation of @addr . */
	time_t stamp; /* Timestamp of receiving the first byte in @buffer . */
} *clients = NULL;

/* Current clients. */
static int num_clients = 0;
/* Max clients. */
static int max_clients = 1024;
/* Max write buffer per a client. */
static int wbuf_size = 65536;
/* Max seconds to wait for new line. */
static int wait_timeout = 10;
/* Try to release unused memory? */
static _Bool try_drop_memory_usage = 0;
/* Name of today's log file. */
static char filename[16] = { };
/* Handle for today's log file. */
static FILE *log_fp = NULL;
/* The mode of log file. */
static mode_t log_perm = 0600;
/* Previous time. */
static struct tm last_tm = { .tm_year = 70, .tm_mday = 1 };

/**
 * die - Print error and exit.
 *
 * @fmt: Format string, followed by arguments.
 * 
 * This function does not return.
 */
static void die(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void die(const char *fmt, ...)
{
	const int err = errno;
	va_list args;
	va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
	fprintf(stderr, " : %s(%d)\n", strerror(err), err);
	exit(1);
}

/**
 * switch_logfile - Close yesterday's log file and open today's log file.
 *
 * @tm: Pointer to "struct tm" holding current time.
 *
 * Returns nothing.
 */
static void switch_logfile(struct tm *tm)
{
	FILE *fp;
	int fd;
	struct stat buf;
	snprintf(filename, sizeof(filename) - 1, "%04u-%02u-%02u.log",
		 tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
	/*
	 * The log file must be a regular file without any executable bits.
	 *
	 * Print error message and exit if the first open() failed.
	 * Otherwise, continue using current log file if open() failed.
	 */
	fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, log_perm);
	if (fd == EOF)
		goto out1;
	if (fstat(fd, &buf))
		goto out1;
	if (!S_ISREG(buf.st_mode) || (buf.st_mode & 0111))
		goto out2;
	fp = fdopen(fd, "a");
	if (!fp)
		goto out1;
	if (log_fp)
		fclose(log_fp);
	log_fp = fp;
	try_drop_memory_usage = 1;
	return;
 out2:
	if (!log_fp) {
		fprintf(stderr, "Log file %s is not a regular file without "
			"executable bits.\n", filename);
		exit(1);
	}
 out1:
	if (!log_fp)
		die("Can't create log file %s", filename);
	if (fd != EOF)
		close(fd);
}

/**
 * write_logfile - Write to today's log file.
 *
 * @ptr:    Pointer to "struct client".
 * @forced: True if the partial line should be written.
 *
 * Returns nothing.
 */
static void write_logfile(struct client *ptr, const _Bool forced)
{
	static time_t last_time = 0;
	static char stamp[24] = { };
	char *buffer = ptr->buffer;
	int avail = ptr->avail;
	const time_t now_time = ptr->stamp;
	if (last_time != now_time) {
		struct tm *tm = localtime(&now_time);
		if (!tm)
			tm = &last_tm;
		snprintf(stamp, sizeof(stamp) - 1, "%04u-%02u-%02u "
			 "%02u:%02u:%02u ", tm->tm_year + 1900, tm->tm_mon + 1,
			 tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
		/*
		 * Switch log file if the day has changed. We can't use
		 * (last_time / 86400 != now_time / 86400) in order to allow
		 * switching at 00:00:00 of the local time.
		 */
		if (tm->tm_mday != last_tm.tm_mday ||
		    tm->tm_mon != last_tm.tm_mon ||
		    tm->tm_year != last_tm.tm_year) {
			last_tm = *tm;
			switch_logfile(tm);
		}
		last_time = now_time;
	}
	/* Write the completed lines. */
	while (1) {
		char *cp = memchr(buffer, '\n', avail);
		const int len = cp - buffer + 1;
		if (!cp)
			break;
		fprintf(log_fp, "%s%s", stamp, ptr->addr_str);
		fwrite(buffer, 1, len, log_fp);
		avail -= len;
		buffer += len;
	}
	/* Write the incomplete line if forced. */
	if (forced && avail) {
		fprintf(log_fp, "%s%s", stamp, ptr->addr_str);
		fwrite(buffer, 1, avail, log_fp);
		fprintf(log_fp, "\n");
		avail = 0;
	}
	/* Discard the written data. */
	if (ptr->buffer != buffer)
		memmove(ptr->buffer, buffer, avail);
	ptr->avail = avail;
}

/**
 * drop_memory_usage - Try to reduce memory usage.
 *
 * Returns nothing.
 */
static void drop_memory_usage(void)
{
	struct client *ptr;
	int i = 0;
	if (!try_drop_memory_usage)
		return;
	try_drop_memory_usage = 0;
	while (i < num_clients) {
		ptr = &clients[i];
		if (ptr->avail) {
			char *tmp = realloc(ptr->buffer, round_up(ptr->avail));
			if (tmp)
				ptr->buffer = tmp;
			i++;
			continue;
		}
		free(ptr->buffer);
		num_clients--;
		memmove(ptr, ptr + 1, (num_clients - i) * sizeof(*ptr));
	}
	if (num_clients) {
		ptr = realloc(clients, round_up(sizeof(*ptr) * num_clients));
		if (ptr)
			clients = ptr;
	} else {
		free(clients);
		clients = NULL;
	}
}

/**
 * flush_all_and_abort - Clean up upon out of memory.
 *
 * This function does not return.
 */
static void flush_all_and_abort(void)
{
	int i;
	for (i = 0; i < num_clients; i++)
		if (clients[i].avail) {
			write_logfile(&clients[i], 1);
			free(clients[i].buffer);
		}
	fprintf(log_fp, "[aborted due to memory allocation failure]\n");
	fflush(log_fp);
	exit(1);
}

/**
 * get_addr - Get string representation of IP address.
 *
 * @ipv6: True if @addr contains an IPv6 address, false otheriwse.
 * @addr: Pointer to "union ipaddr".
 *
 * Returns static buffer to IP string.
 */
static const char *get_addr(_Bool ipv6, const union ipaddr *addr)
{
	static char buf[40];
	memset(buf, 0, sizeof(buf));
	if (ipv6)
		inet_ntop(AF_INET6, &addr->ip6.sin6_addr, buf, sizeof(buf));
	else
		inet_ntop(AF_INET, &addr->ip4.sin_addr, buf, sizeof(buf));
	return buf;
}

/**
 * find_client - Find the structure for given address.
 *
 * @addr: Pointer to "union ipaddr".
 * @size: Valid bytes in @addr .
 *
 * Returns "struct client" for @addr on success, NULL otherwise.
 */
static struct client *find_client(union ipaddr *addr, socklen_t size)
{
	struct client *ptr;
	const char *ip;
	_Bool ipv6 = 0;
	int i;
	if (size == sizeof(struct sockaddr_in)) {
		if (addr->ip4.sin_family != AF_INET)
			return NULL;
	} else if (size == sizeof(struct sockaddr_in6)) {
		if (addr->ip6.sin6_family != AF_INET6)
			return NULL;
		/* Use IPv4 format for v4-mapped-v6 address. */
		if ((addr->ip6.sin6_addr.s6_addr32[0] |
		     addr->ip6.sin6_addr.s6_addr32[1] |
		     (addr->ip6.sin6_addr.s6_addr32[2] ^
		      htonl(0x0000ffff))) == 0) {
			size = sizeof(struct sockaddr_in);
			addr->ip4.sin_family = AF_INET;
			addr->ip4.sin_port = addr->ip6.sin6_port;
			memmove(&addr->ip4.sin_addr.s_addr,
				&addr->ip6.sin6_addr.s6_addr[12], 4);
		} else
			ipv6 = 1;
	} else {
		return NULL;
	}
	for (i = 0; i < num_clients; i++)
		if (clients[i].size == size &&
		    !memcmp(&clients[i].addr, addr, size))
			return &clients[i];
	if (i >= max_clients) {
		try_drop_memory_usage = 1;
		drop_memory_usage();
		if (i >= max_clients)
			return NULL;
	}
	ptr = realloc(clients, round_up(sizeof(*ptr) * (num_clients + 1)));
	if (!ptr)
		return NULL;
	clients = ptr;
	ptr = &clients[num_clients++];
	memset(ptr, 0, sizeof(*ptr));
	ptr->size = size;
	memmove(&ptr->addr, addr, size);
	ip = get_addr(ipv6, addr);
	if (ipv6)
		snprintf(ptr->addr_str, sizeof(ptr->addr_str) - 1,
			 "[%s]:%u ", ip, ntohs(addr->ip6.sin6_port));
	else
		snprintf(ptr->addr_str, sizeof(ptr->addr_str) - 1, "%s:%u ",
			 ip, ntohs(addr->ip4.sin_port));
	return ptr;
}

/**
 * do_main - The main loop.
 *
 * @fd: Receiver socket's file descriptor.
 *
 * Returns nothing.
 */
static void do_main(const int fd)
{
	static char buf[65536];
	while (1) {
		struct pollfd pfd = { fd, POLLIN, 0 };
		int i;
		time_t now;
		/* Don't wait forever if checking for timeout. */
		for (i = 0; i < num_clients; i++)
			if (clients[i].avail)
				break;
		/* Flush log file and wait for data. */
		fflush(log_fp);
		poll(&pfd, 1, i < num_clients ? 1000 : -1);
		now = time(NULL);
		/* Check for timeout. */
		for (i = 0; i < num_clients; i++)
			if (clients[i].avail &&
			    now - clients[i].stamp >= wait_timeout)
				write_logfile(&clients[i], 1);
		/* Don't receive forever in order to check for timeout. */
		while (now == time(NULL)) {
			struct client *ptr;
			char *tmp;
			union ipaddr addr;
			socklen_t size = sizeof(addr);
			int len = recvfrom(fd, buf, sizeof(buf), MSG_DONTWAIT,
					   (struct sockaddr *) &addr, &size);
			if (len <= 0)
				break;
			ptr = find_client(&addr, size);
			if (!ptr)
				continue;
			/* Save current time if receiving the first byte. */
			if (!ptr->avail)
				ptr->stamp = now;
			/* Append data to the line. */
			tmp = realloc(ptr->buffer, round_up(ptr->avail + len));
			if (!tmp)
				flush_all_and_abort();
			memmove(tmp + ptr->avail, buf, len);
			ptr->avail += len;
			ptr->buffer = tmp;
			/* Write if at least one line completed. */
			if (memchr(buf, '\n', len))
				write_logfile(ptr, 0);
			/* Write if the line is too long. */
			if (ptr->avail >= wbuf_size)
				write_logfile(ptr, 1);
		}
		drop_memory_usage();
	}
}

/**
 * usage - Print usage and exit.
 *
 * @name: Program's name.
 *
 * This function does not return.
 */
static void usage(const char *name)
{
	fprintf(stderr, "Simple UDP logger\n\n"
		"Usage:\n  %s [ip=$listen_ip] [port=$listen_port] "
		"[dir=$log_dir] [timeout=$seconds_waiting_for_newline] "
		"[clients=$max_clients] [wbuf=$write_buffer_size] "
		"[rbuf=$receive_buffer_size] [uid=$user_id] [gid=$group_id] "
		"[perm=$log_perm]\n\nPlease see the README file.\n", name);
	exit (1);
}

/**
 * do_init - Initialization function.
 *
 * @argc: Number of arguments.
 * @argv: Arguments.
 *
 * Returns the listener socket's file descriptor.
 */
static int do_init(int argc, char *argv[])
{
	union ipaddr addr = { };
	char pwd[4096];
	/* Max receive buffer size. */
	int rbuf_size = 8 * 1048576;
	socklen_t size;
	int fd = EOF;
	int i;
	/* Directory to save logs. */
	const char *log_dir = ".";
	/* Address to listen. */
	_Bool ipv6 = 1;
	const char *ip = NULL;
	unsigned short port = 6666;
	uid_t user_id = getuid();
	gid_t group_id = getgid();
	struct tm *tm = NULL;
	for (i = 1; i < argc; i++) {
		char *arg = argv[i];
		if (!strncmp(arg, "ip=", 3))
			ip = arg + 3;
		else if (!strncmp(arg, "port=", 5))
			port = atoi(arg + 5);
		else if (!strncmp(arg, "dir=", 4))
			log_dir = arg + 4;
		else if (!strncmp(arg, "timeout=", 8))
			wait_timeout = atoi(arg + 8);
		else if (!strncmp(arg, "clients=", 8))
			max_clients = atoi(arg + 8);
		else if (!strncmp(arg, "wbuf=", 5))
			wbuf_size = atoi(arg + 5);
		else if (!strncmp(arg, "rbuf=", 5))
			rbuf_size = atoi(arg + 5);
		else if (!strncmp(arg, "uid=", 4))
			user_id = atoi(arg + 4);
		else if (!strncmp(arg, "gid=", 4))
			group_id = atoi(arg + 4);
		else if (!strncmp(arg, "perm=", 5))
			log_perm = strtol(arg + 5, NULL, 8) & 0666;
		else
			usage(argv[0]);
	}
	/* Sanity check. */
	if (max_clients < 10)
		max_clients = 10;
	if (max_clients > 65536)
		max_clients = 65536;
	if (wait_timeout < 5)
		wait_timeout = 5;
	if (wait_timeout > 600)
		wait_timeout = 600;
	if (wbuf_size < 1024)
		wbuf_size = 1024;
	if (wbuf_size > 1048576)
		wbuf_size = 1048576;
	if (rbuf_size < 65536)
		rbuf_size = 65536;
	if (rbuf_size > 1024 * 1048576)
		rbuf_size = 1024 * 1048576;
	/* Create the listener socket and configure it. */
	if (!ip || inet_pton(AF_INET, ip, &addr.ip4.sin_addr) != 1) {
		fd = socket(PF_INET6, SOCK_DGRAM, 0);
		/*
		 * Give up if IPv6 address was requested but IPv6 socket is not
		 * available.
		 */
		if (fd == EOF && ip)
			die("Can't create IPv6 socket");
	}
	if (fd == EOF) {
		fd = socket(PF_INET, SOCK_DGRAM, 0);
		/* Give up if IPv4 socket is not available. */
		if (fd == EOF)
			die("Can't create IPv4 socket");
		ipv6 = 0;
	}
	if (ipv6) {
		addr.ip6.sin6_family = AF_INET6;
		addr.ip6.sin6_port = htons(port);
		if (!ip)
			addr.ip6.sin6_addr = in6addr_any;
		else if (inet_pton(AF_INET6, ip, &addr.ip6.sin6_addr) != 1) {
			fprintf(stderr, "%s is an Invalid IPv6 address\n", ip);
			exit(1);
		}
	} else {
		addr.ip4.sin_family = AF_INET;
		addr.ip4.sin_port = htons(port);
		if (!ip)
			addr.ip4.sin_addr.s_addr = htonl(INADDR_ANY);
	}
#ifdef SO_RCVBUFFORCE
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rbuf_size,
		       sizeof(rbuf_size)))
#endif
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rbuf_size,
			       sizeof(rbuf_size)))
			die("Can't set receive buffer size");
	size = sizeof(rbuf_size);
	if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rbuf_size, &size))
		die("Can't get receive buffer size");
	ip = get_addr(ipv6, &addr);
	if (ipv6)
		port = ntohs(addr.ip6.sin6_port);
	else
		port = ntohs(addr.ip4.sin_port);
	size = ipv6 ? sizeof(addr.ip6) : sizeof(addr.ip4);
	if (bind(fd, (struct sockaddr *) &addr, size))
		die("Can't bind to ip=%s port=%u", ip, port);
	else if (getsockname(fd, (struct sockaddr *) &addr, &size))
		die("Can't get bound address");
	ip = get_addr(ipv6, &addr);
	if (ipv6)
		port = ntohs(addr.ip6.sin6_port);
	else
		port = ntohs(addr.ip4.sin_port);
	/* Open the initial log file. */
	memset(pwd, 0, sizeof(pwd));
	if (chdir(log_dir) || !getcwd(pwd, sizeof(pwd) - 1))
		die("Can't change directory to %s", log_dir);
	setgid(group_id); /* We can ignore errors here. */
	if (getgid() != group_id)
		die("Can't change group ID to %d", group_id);
	setuid(user_id); /* We can ignore errors here. */
	if (getuid() != user_id)
		die("Can't change user ID to %d", user_id);
	{
		const time_t now = time(NULL);
		tm = localtime(&now);
		if (!tm)
			tm = &last_tm;
		umask(0);
		switch_logfile(tm);
	}
	/* Successfully initialized. */
	printf("Started at %04u-%02u-%02u %02u:%02u:%02u from %s/%s ",
	       tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour,
	       tm->tm_min, tm->tm_sec, pwd, filename);
	printf("using options ip=%s port=%u dir=%s timeout=%u clients=%u "
	       "wbuf=%u rbuf=%u uid=%u gid=%u perm=0%03o\n", ip, port, pwd,
	       wait_timeout, max_clients, wbuf_size, rbuf_size, user_id,
	       group_id, log_perm);
	return fd;
}

int main(int argc, char *argv[])
{
	const int fd = do_init(argc, argv);
	do_main(fd);
	return 0;
}
