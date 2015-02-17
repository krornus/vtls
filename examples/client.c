/*
 * Copyright(c) 2015 Tim Ruehsen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * This file is part of libvtls.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <vtls.h>
#include <netdb.h>

#include "src/backend.h"

#define HTTP_REQUEST \
"GET / HTTP/1.1\r\n"\
"Host: www.google.com\r\n"\
"Accept: */*\r\n"\
"\r\n"

/* timeouts in milliseconds */
#define CONNECT_TIMEOUT 30*1000
#define WRITE_TIMEOUT   10*1000
#define READ_TIMEOUT    25*1000

static int _get_connected_socket(const char *host, int port);
static void _debugmsg(vtls_connection_t *conn, const char *fmt, va_list args);
static void _errormsg(vtls_connection_t *conn, const char *fmt, va_list args);
static void _debug_printf(vtls_connection_t *conn, const char *fmt, ...);
static void _error_printf(vtls_connection_t *conn, const char *fmt, ...);

/* for multi-threaded environments */
/*
#include <pthread.h>
static pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;
void _set_mutex(int lock)
{
	if (lock)
		pthread_mutex_lock(_mutex);
	else
		pthread_mutex_unlock(_mutex);
}
*/

int main(int argc, const char *const *argv)
{
	vtls_session_t *sess = NULL;
	vtls_connection_t *conn = NULL;
	int rc, sockfd;
	ssize_t nbytes;
	char buf[2048];
	const char *hostname = "www.google.com";

	sockfd = _get_connected_socket(hostname, 443);

	/*
	 * Plain text connection has been established.
	 * Before we establish the TLS layer, we could send/recv plain text here.
	 */

	/*
	 * There global settings that (maybe) need to be set before vtls_init().
	 * Every created session will inherit these settings, but you can change them
	 * for each session separately as you want.
	 */
	vtls_glob_set_error_callback(_errormsg);
	vtls_glob_set_debug_callback(_debugmsg);
	// vtls_global_set_lock_callback(_set_mutex); /* only needed for multi-threaded environments */

	/*
	 * vtls_init() can not be thread-safe without a locking mechanism.
	 * So either
	 * - call vtls_init() outside (before) threading
	 * - wrap vtls_init() into your own locking/unlocking mechanism
	 * - provide a vtls_lock_callback_t object/function to vtls_init()
	 *
	 * The two last options allow calling vtls_init() more than once without side-effects.
	 */
	if (vtls_init()) {
		_error_printf(NULL, "Failed to init vtls\n");
		return 1;
	}

	if ((rc = vtls_session_init(&sess))) {
		_error_printf(NULL, "Failed to init vtls session (%d)\n", rc);
		return 1;
	}

	/* session specific settings */
	vtls_set_tls_version(sess, VTLS_TLSVERSION_TLSv1_0);
	vtls_set_ca_file(sess, "/etc/ssl/certs"); /* directory or file to all the CA certificates to check */

	if ((rc = vtls_connection_init(&conn, sess, sockfd))) {
		_error_printf(NULL, "Failed to init connection (%d)\n", rc);
		return 1;
	}

	/* connection specific settings */
	vtls_conn_set_sni_hostname(conn, hostname);
	// vtls_set_max_timeout(conn, 60*1000); /* 60s timeout allowed in total */
	// vtls_set_connect_timeout(conn, 30*1000); /* 30s timeout */
	// vtls_set_read_timeout(conn, 10*1000); /* 10s timeout */
	// vtls_set_write_timeout(conn, 10*1000); /* 10s timeout */

	if ((rc = vtls_connect(conn))) {
		_error_printf(conn, "Failed to connect (%d)\n", rc);
		return 1;
	}
	_debug_printf(conn, "connection established\n");

	/* for a nonblocking write set */
	if ((nbytes = vtls_write(conn, HTTP_REQUEST, sizeof(HTTP_REQUEST) - 1)) < 0) {
		_error_printf(conn, "Failed to write (%d)\n", vtls_get_status_code(conn));
		return 1;
	}
	_debug_printf(conn, "data written (%zd bytes)\n", nbytes);

	while ((nbytes = vtls_read(conn, buf, sizeof(buf))) >= 0) {
		fwrite(buf, 1, nbytes, stdout);
	}

	vtls_close(conn);

	vtls_connection_deinit(conn);

	vtls_session_deinit(sess);

	vtls_deinit();

	/*
	 * TLS connection has been shut down, but the TCP/IP connection is still valid.
	 * We could again send/recv plain text here.
	 */

	close(sockfd);

	return 0;
}

#ifndef SOCK_NONBLOCK
static void _set_async(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) < 0)
		_error_printf(NULL, "Failed to get socket flags\n");

	if (fcntl(fd, F_SETFL, flags | O_NDELAY) < 0)
		_error_printf(NULL, "Failed to set socket to non-blocking\n");
}
#endif

static int _get_async_socket(void)
{
	int sockfd;

#ifdef SOCK_NONBLOCK
	if ((sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) != -1) {
#else
	int on = 1;

	if ((sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) != -1) {
		int on = 1;

		_set_async(sockfd);
#endif
/*
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on)) == -1)
			_error_printf(NULL, "Failed to set socket option REUSEADDR\n");

		on = 1;
		if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void *)&on, sizeof(on)) == -1)
			_error_printf(NULL, "Failed to set socket option NODELAY\n");
*/
	}

	return sockfd;
}

static int _get_connected_socket(const char *host, int port)
{
	struct addrinfo *addrinfo, hints;
	int rc, sockfd;
	char s_port[16];

	memset(&hints, 0 ,sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;

	snprintf(s_port, sizeof(s_port), "%d", port);
	if ((rc = getaddrinfo(host, s_port, &hints, &addrinfo))) {
		_error_printf(NULL, "Failed to resolve %s\n", host);
		return rc;
	}

	if ((sockfd = _get_async_socket()) < 0) {
		_error_printf(NULL, "Failed to get socket\n");
		freeaddrinfo(addrinfo);
		return rc;
	}

	if ((rc = connect(sockfd, addrinfo->ai_addr, addrinfo->ai_addrlen))
		&& errno != EAGAIN
#ifdef EINPROGRESS
		&& errno != EINPROGRESS
#endif
		)
	{
		_error_printf(NULL, "Failed to get socket\n");
		freeaddrinfo(addrinfo);
		return rc;
	}


	freeaddrinfo(addrinfo);
	return sockfd;
}

/* conn may be NULL. That indicates connection independent (global) messages. */
static void _debugmsg(vtls_connection_t *conn, const char *fmt, va_list args)
{
	char buf[2048];
	struct timeval tv;
	struct tm *tp, tbuf;

	gettimeofday(&tv, NULL); // obsoleted by POSIX.1-2008, maybe use clock_gettime() ? needs -lrt
	tp = localtime_r((const time_t *)&tv.tv_sec, &tbuf); // cast avoids warning on OpenBSD

	vsnprintf(buf, sizeof(buf), fmt, args);

	if (conn)
		printf("[%d] %02d:%02d:%02d.%03ld %s",
			conn->sockfd,
			tp->tm_hour, tp->tm_min, tp->tm_sec, tv.tv_usec / 1000, buf);
	else
		printf("%02d:%02d:%02d.%03ld %s",
			tp->tm_hour, tp->tm_min, tp->tm_sec, tv.tv_usec / 1000, buf);

}

static void _errormsg(vtls_connection_t *conn, const char *fmt, va_list args)
{
	_debugmsg(conn, fmt, args);
}

static void _debug_printf(vtls_connection_t *conn, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	_debugmsg(conn, fmt, args);
	va_end(args);
}

static void _error_printf(vtls_connection_t *conn, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	_errormsg(conn, fmt, args);
	va_end(args);
}

