/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/*
 * Source file for all GnuTLS-specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 *
 * Note: don't use the GnuTLS' *_t variable type names in this source code,
 * since they were not present in 1.0.X.
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "common.h"
#include "timeval.h"
#include "select.h"
#include "inet_pton.h"
#include "backend.h"

#ifdef USE_GNUTLS_NETTLE
#include <gnutls/crypto.h>
#include <nettle/md5.h>
#else
#include <gcrypt.h>
#endif

/*
 Some hackish cast macros based on:
 http://library.gnome.org/devel/glib/unstable/glib-Type-Conversion-Macros.html
 */
#ifndef GNUTLS_POINTER_TO_INT_CAST
#define GNUTLS_POINTER_TO_INT_CAST(p) ((int) (long) (p))
#endif
#ifndef GNUTLS_INT_TO_POINTER_CAST
#define GNUTLS_INT_TO_POINTER_CAST(i) ((void*) (long) (i))
#endif

struct backend_session_data {
	gnutls_session_t session;
	gnutls_certificate_credentials_t cred;
	gnutls_certificate_credentials_t srp_client_cred;
};
static int _init_backend = 0;

#if defined(GNUTLS_VERSION_NUMBER)
#if (GNUTLS_VERSION_NUMBER >= 0x020c00)
#undef gnutls_transport_set_lowat
#define gnutls_transport_set_lowat(A,B) Curl_nop_stmt
#define USE_GNUTLS_PRIORITY_SET_DIRECT 1
#endif
#if (GNUTLS_VERSION_NUMBER >= 0x020c03)
#define GNUTLS_MAPS_WINSOCK_ERRORS 1
#endif

#ifdef USE_NGHTTP2
#undef HAS_ALPN
#if (GNUTLS_VERSION_NUMBER >= 0x030200)
#define HAS_ALPN
#endif
#endif

#if (GNUTLS_VERSION_NUMBER >= 0x03020d)
#define HAS_OCSP
#endif
#endif

#ifdef HAS_OCSP
#include <gnutls/ocsp.h>
#endif

/*
 * Custom push and pull callback functions used by GNU TLS to read and write
 * to the socket.  These functions are simple wrappers to send() and recv()
 * (although here using the sread/swrite macros as defined by
 * curl_setup_once.h).
 * We use custom functions rather than the GNU TLS defaults because it allows
 * us to get specific about the fourth "flags" argument, and to use arbitrary
 * private data with gnutls_transport_set_ptr if we wish.
 *
 * When these custom push and pull callbacks fail, GNU TLS checks its own
 * session-specific error variable, and when not set also its own global
 * errno variable, in order to take appropriate action. GNU TLS does not
 * require that the transport is actually a socket. This implies that for
 * Windows builds these callbacks should ideally set the session-specific
 * error variable using function gnutls_transport_set_errno or as a last
 * resort global errno variable using gnutls_transport_set_global_errno,
 * with a transport agnostic error value. This implies that some winsock
 * error translation must take place in these callbacks.
 *
 * Paragraph above applies to GNU TLS versions older than 2.12.3, since
 * this version GNU TLS does its own internal winsock error translation
 * using system_errno() function.
 */

#if defined(USE_WINSOCK) && !defined(GNUTLS_MAPS_WINSOCK_ERRORS)
#define gtls_EINTR  4
#define gtls_EIO    5
#define gtls_EAGAIN 11

static int gtls_mapped_sockerrno(void)
{
	switch (SOCKERRNO) {
	case WSAEWOULDBLOCK:
		return gtls_EAGAIN;
	case WSAEINTR:
		return gtls_EINTR;
	default:
		break;
	}
	return gtls_EIO;
}
#endif

static ssize_t vtls_push(void *s, const void *buf, size_t len)
{
	ssize_t ret = write(GNUTLS_POINTER_TO_INT_CAST(s), buf, len);
#if defined(USE_WINSOCK) && !defined(GNUTLS_MAPS_WINSOCK_ERRORS)
	if (ret < 0)
		gnutls_transport_set_global_errno(gtls_mapped_sockerrno());
#endif
	error_printf(NULL, "[%d] w len=%zd ret=%zd\n",GNUTLS_POINTER_TO_INT_CAST(s), len, ret);
	return ret;
}

static ssize_t vtls_pull(void *s, void *buf, size_t len)
{
	ssize_t ret = read(GNUTLS_POINTER_TO_INT_CAST(s), buf, len);
#if defined(USE_WINSOCK) && !defined(GNUTLS_MAPS_WINSOCK_ERRORS)
	if (ret < 0)
		gnutls_transport_set_global_errno(gtls_mapped_sockerrno());
#endif
	error_printf(NULL, "[%d] r len=%zd ret=%zd\n",GNUTLS_POINTER_TO_INT_CAST(s), len, ret);
	return ret;
}

int backend_get_engine(void)
{
	return CURLSSLBACKEND_GNUTLS;
}

/* backend_init()
 *
 * Called from vtls_init().
 * In a multi-threaded szenario, the lock funtion must have been set
 * before calling vtls_init().
 */
int backend_init(void)
{
	int ret = 1;

	if (_init_backend++ == 0) {
		if ((ret = gnutls_global_init()) == 0) {
#ifdef GTLSDEBUG
			gnutls_global_set_log_function(tls_log_func);
			gnutls_global_set_log_level(2);
#endif
		}
	}

	return ret;
}

int backend_deinit(void)
{
	if (--_init_backend == 0)
		gnutls_global_deinit();

	return 0;
}

int backend_session_init(vtls_session_t *sess)
{
	if (!(sess->backend_data = calloc(1, sizeof(struct backend_session_data))))
		return -2;

	return 0;
}

void backend_session_deinit(vtls_session_t *sess)
{
	xfree(sess->backend_data);
}

static void showtime(vtls_connection_t *conn, const char *text, time_t stamp)
{
	struct tm buffer;
	const struct tm *tm = &buffer;
//	int result = Curl_gmtime(stamp, &buffer);

	gmtime_r(&stamp, &buffer);

//	if (result)
//		return;

//	debug_printf(sess->config, "\t %s: %s, %02d %s %4d %02d:%02d:%02d GMT\n",
	debug_printf(conn, "\t %s: %d.%d.%d %02d:%02d:%02d GMT\n",
		text,
		tm->tm_mday, tm->tm_mon + 1, tm->tm_year + 1900,
		tm->tm_hour, tm->tm_min, tm->tm_sec);
}

static gnutls_datum_t load_file(const char *file)
{
	FILE *f;
	gnutls_datum_t loaded_file = {NULL, 0};
	long filelen;
	void *ptr;

	if (!(f = fopen(file, "r")))
		return loaded_file;
	if (fseek(f, 0, SEEK_END) != 0
		|| (filelen = ftell(f)) < 0
		|| fseek(f, 0, SEEK_SET) != 0
		|| !(ptr = malloc((size_t) filelen)))
		goto out;
	if (fread(ptr, 1, (size_t) filelen, f) < (size_t) filelen) {
		free(ptr);
		goto out;
	}

	loaded_file.data = ptr;
	loaded_file.size = (unsigned int) filelen;
out:
	fclose(f);
	return loaded_file;
}

static void unload_file(gnutls_datum_t data)
{
	free(data.data);
}

/* this function does a SSL/TLS (re-)handshake */
static int handshake(vtls_connection_t *conn, int nonblocking)
{
	vtls_session_t *sess = conn->session;
	struct backend_session_data *backend = sess->backend_data;
	int sockfd = conn->sockfd;
	long timeout_ms;
	int rc;

	for (;;) {
		/* check allowed time left */
		timeout_ms = vtls_timeleft_ms(&conn->connect_start, conn->connect_timeout);

		if (timeout_ms < 0) {
			/* no need to continue if time already is up */
			error_printf(conn, "TLS connection timeout\n");
			return CURLE_OPERATION_TIMEDOUT;
		}

		/* if ssl is expecting something, check if it's available. */
		if (conn->connecting_state == ssl_connect_2_reading
			|| conn->connecting_state == ssl_connect_2_writing)
		{
			int writefd = ssl_connect_2_writing == conn->connecting_state ? sockfd : -1;
			int readfd = ssl_connect_2_reading == conn->connecting_state ? sockfd : -1;
			int what = Curl_socket_ready(readfd, writefd, timeout_ms);

			if (what < 0) {
				/* fatal error */
				error_printf(conn, "select/poll on TLS socket, errno: %d\n", SOCKERRNO);
				return CURLE_SSL_CONNECT_ERROR;
			} else if (0 == what) {
				if (nonblocking)
					return 0;
				else if (timeout_ms) {
					/* timeout */
					error_printf(conn, "TLS connection timeout at %ld\n", timeout_ms);
					return CURLE_OPERATION_TIMEDOUT;
				}
			}
			/* socket is readable or writable */
		}

		rc = gnutls_handshake(backend->session);

		if ((rc == GNUTLS_E_AGAIN) || (rc == GNUTLS_E_INTERRUPTED)) {
			conn->connecting_state = gnutls_record_get_direction(backend->session) ?
				ssl_connect_2_writing : ssl_connect_2_reading;
			continue;
		} else if ((rc < 0) && !gnutls_error_is_fatal(rc)) {
			const char *strerr = NULL;

			if (rc == GNUTLS_E_WARNING_ALERT_RECEIVED) {
				int alert = gnutls_alert_get(backend->session);
				strerr = gnutls_alert_get_name(alert);
			}

			if (strerr == NULL)
				strerr = gnutls_strerror(rc);

			debug_printf(conn, "gnutls_handshake() warning: %s\n", strerr);
		} else if (rc < 0) {
			const char *strerr = NULL;

			if (rc == GNUTLS_E_FATAL_ALERT_RECEIVED) {
				int alert = gnutls_alert_get(backend->session);
				strerr = gnutls_alert_get_name(alert);
			}

			if (strerr == NULL)
				strerr = gnutls_strerror(rc);

			error_printf(conn, "gnutls_handshake() failed: %s\n", strerr);
			return CURLE_SSL_CONNECT_ERROR;
		}

		/* Reset our connect state machine */
		conn->connecting_state = ssl_connect_1;
		return 0;
	}
}

static gnutls_x509_crt_fmt_t do_file_type(int type)
{
	if (type == VTLS_FILETYPE_PEM)
		return GNUTLS_X509_FMT_PEM;
	if (type == VTLS_FILETYPE_DER)
		return GNUTLS_X509_FMT_DER;
	return -1;
}

static int
gtls_connect_step1(vtls_connection_t *conn)
{
//	struct SessionHandle *data = conn->data;
	vtls_session_t *sess = conn->session;
	struct backend_session_data *backend = sess->backend_data;
	const char *ca_file = sess->config->CAfile;
	int rc;
	int sni = 1; /* default is SNI enabled */
#ifdef ENABLE_IPV6
	struct in6_addr addr;
#else
	struct in_addr addr;
#endif
#ifndef USE_GNUTLS_PRIORITY_SET_DIRECT
	static const int cipher_priority[] = {
		/* These two ciphers were added to GnuTLS as late as ver. 3.0.1,
			but this code path is only ever used for ver. < 2.12.0.
			GNUTLS_CIPHER_AES_128_GCM,
			GNUTLS_CIPHER_AES_256_GCM,
		 */
		GNUTLS_CIPHER_AES_128_CBC,
		GNUTLS_CIPHER_AES_256_CBC,
		GNUTLS_CIPHER_CAMELLIA_128_CBC,
		GNUTLS_CIPHER_CAMELLIA_256_CBC,
		GNUTLS_CIPHER_3DES_CBC,
	};
	static const int cert_type_priority[] = {GNUTLS_CRT_X509, 0};
	static int protocol_priority[] = {0, 0, 0, 0};
#else
#define GNUTLS_CIPHERS "NORMAL:-ARCFOUR-128:-CTYPE-ALL:+CTYPE-X509"
	/* If GnuTLS was compiled without support for SRP it will error out if SRP is
		requested in the priority string, so treat it specially
	 */
#define GNUTLS_SRP "+SRP"
	const char *prioritylist;
	const char *err = NULL;
#endif

	if (conn->state == ssl_connection_complete)
		/* to make us tolerant against being called more than once for the
			same connection */
		return 0;

	/* GnuTLS only supports SSLv3 and TLSv1 */
	if (sess->config->version == VTLS_TLSVERSION_SSLv2) {
		error_printf(conn, "GnuTLS does not support SSLv2\n");
		return CURLE_SSL_CONNECT_ERROR;
	} else if (sess->config->version == VTLS_TLSVERSION_SSLv3)
		sni = 0; /* SSLv3 has no SNI */

	/* allocate a cred struct */
	rc = gnutls_certificate_allocate_credentials(&backend->cred);
	if (rc != GNUTLS_E_SUCCESS) {
		error_printf(conn, "gnutls_cert_all_cred() failed: %s\n", gnutls_strerror(rc));
		return CURLE_SSL_CONNECT_ERROR;
	}

#ifdef USE_TLS_SRP
	if (sess->config->authtype == CURL_TLSAUTH_SRP) {
		debug_printf(conn, "Using TLS-SRP username: %s\n", data->set.ssl.username);

		rc = gnutls_srp_allocate_client_credentials(&sess->srp_client_cred);
		if (rc != GNUTLS_E_SUCCESS) {
			error_printf(conn, "gnutls_srp_allocate_client_cred() failed: %s\n", gnutls_strerror(rc));
			return CURLE_OUT_OF_MEMORY;
		}

		rc = gnutls_srp_set_client_credentials(sess->srp_client_cred,
			data->set.ssl.username,
			data->set.ssl.password);
		if (rc != GNUTLS_E_SUCCESS) {
			error_printf(conn, "gnutls_srp_set_client_cred() failed: %s\n", gnutls_strerror(rc));
			return CURLE_BAD_FUNCTION_ARGUMENT;
		}
	}
#endif

	if (ca_file) {
		rc = -1;
		if (!strcmp(ca_file, "system")) {
#if GNUTLS_VERSION_NUMBER >= 0x030014
			rc = gnutls_certificate_set_x509_system_trust(backend->cred);
			if (rc < 0) {
				error_printf(conn, "error reading system CA cert dir (%s)\n", gnutls_strerror(rc));
				return CURLE_SSL_CACERT_BADFILE;
			}
			debug_printf(conn, "found %d certificates in system CA cert dir\n", rc);
#else
		error_printf(conn, "system CA cert dir not supported - GnuTLS version too old\n");
#endif
		}

		if (rc < 0) {
			struct stat st;

			if (stat(ca_file, &st) == 0 && S_ISDIR(st.st_mode)) {
				/* read each PEM file from directory */
				DIR *dir;
				int ncerts = 0;

				if ((dir = opendir(ca_file))) {
					struct dirent *dp;
					size_t dirlen = strlen(ca_file);

					while ((dp = readdir(dir))) {
						size_t len = strlen(dp->d_name);

						if (len >= 4 && !strncasecmp(dp->d_name + len - 4, ".pem", 4)) {
							struct stat st;
							char fname[dirlen + 1 + len + 1];

							snprintf(fname, sizeof(fname), "%s/%s", ca_file, dp->d_name);
							if (stat(fname, &st) == 0 && S_ISREG(st.st_mode)) {
								int rc;

								if ((rc = gnutls_certificate_set_x509_trust_file(backend->cred, fname, GNUTLS_X509_FMT_PEM)) <= 0)
									error_printf(conn, "failed to load CA cert '%s': (%d)\n", fname, rc);
								else
									ncerts += rc;
							}
						}
					}

					closedir(dir);
				} else {
					error_printf(conn, "failed to open CA cert dir %s\n", ca_file);
				}

				debug_printf(conn, "found %d certificates in CA cert dir '%s'\n", ncerts, ca_file);
			} else {
				/* set the trusted CA cert bundle file */
				gnutls_certificate_set_verify_flags(backend->cred, GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT);

				rc = gnutls_certificate_set_x509_trust_file(backend->cred, ca_file, GNUTLS_X509_FMT_PEM);
				if (rc < 0) {
					error_printf(conn, "error reading CA cert file %s (%s)\n", ca_file, gnutls_strerror(rc));
					if (sess->config->verifypeer)
						return CURLE_SSL_CACERT_BADFILE;
				} else
					debug_printf(conn, "found %d certificates in CA cert file '%s'\n", rc, ca_file);
			}
		}
	}

	if (sess->config->CRLfile) {
		/* set the CRL list file */
		rc = gnutls_certificate_set_x509_crl_file(backend->cred, sess->config->CRLfile, GNUTLS_X509_FMT_PEM);
		if (rc < 0) {
			error_printf(conn, "error reading crl file %s (%s)", sess->config->CRLfile, gnutls_strerror(rc));
			return CURLE_SSL_CRL_BADFILE;
		} else
			debug_printf(conn, "found %d CRL in %s\n", rc, sess->config->CRLfile);
	}

	/* Initialize TLS session as a client */
	rc = gnutls_init(&backend->session, GNUTLS_CLIENT);
	if (rc != GNUTLS_E_SUCCESS) {
		error_printf(conn, "gnutls_init() failed: %d", rc);
		return CURLE_SSL_CONNECT_ERROR;
	}

	if (conn->hostname) {
		if (Curl_inet_pton(AF_INET, conn->hostname, &addr) == 0 &&
#ifdef ENABLE_IPV6
			(Curl_inet_pton(AF_INET6, conn->hostname, &addr) == 0 &&
#endif
			sni &&
			gnutls_server_name_set(backend->session, GNUTLS_NAME_DNS, conn->hostname, strlen(conn->hostname)) < 0)
		{
			error_printf(conn, "WARNING: failed to configure server name indication (SNI) TLS extension\n");
		}
	}

	/* Use default priorities */
	rc = gnutls_set_default_priority(backend->session);
	if (rc != GNUTLS_E_SUCCESS)
		return CURLE_SSL_CONNECT_ERROR;

#ifndef USE_GNUTLS_PRIORITY_SET_DIRECT
	rc = gnutls_cipher_set_priority(backend->session, cipher_priority);
	if (rc != GNUTLS_E_SUCCESS)
		return CURLE_SSL_CONNECT_ERROR;

	/* Sets the priority on the certificate types supported by gnutls. Priority
	 is higher for types specified before others. After specifying the types
	 you want, you must append a 0. */
	rc = gnutls_certificate_type_set_priority(backend->session, cert_type_priority);
	if (rc != GNUTLS_E_SUCCESS)
		return CURLE_SSL_CONNECT_ERROR;

	if (data->set.ssl.cipher_list != NULL) {
		error_printf(conn, "can't pass a custom cipher list to older GnuTLS versions\n");
		return CURLE_SSL_CONNECT_ERROR;
	}

	switch (data->set.ssl.version) {
	case VTLS_TLSVERSION_SSLv3:
		protocol_priority[0] = GNUTLS_SSL3;
		break;
	case VTLS_TLSVERSION_DEFAULT:
	case VTLS_TLSVERSION_TLSv1:
		protocol_priority[0] = GNUTLS_TLS1_0;
		protocol_priority[1] = GNUTLS_TLS1_1;
		protocol_priority[2] = GNUTLS_TLS1_2;
		break;
	case VTLS_TLSVERSION_TLSv1_0:
		protocol_priority[0] = GNUTLS_TLS1_0;
		break;
	case VTLS_TLSVERSION_TLSv1_1:
		protocol_priority[0] = GNUTLS_TLS1_1;
		break;
	case VTLS_TLSVERSION_TLSv1_2:
		protocol_priority[0] = GNUTLS_TLS1_2;
		break;
	case VTLS_TLSVERSION_SSLv2:
	default:
		error_printf(conn, "GnuTLS does not support SSLv2\n");
		return CURLE_SSL_CONNECT_ERROR;
		break;
	}
	rc = gnutls_protocol_set_priority(backend->session, protocol_priority);
	if (rc != GNUTLS_E_SUCCESS) {
		error_printf(conn, "Did you pass a valid GnuTLS cipher list?\n");
		return CURLE_SSL_CONNECT_ERROR;
	}

#else
	/* Ensure +SRP comes at the *end* of all relevant strings so that it can be
	 * removed if a run-time error indicates that SRP is not supported by this
	 * GnuTLS version */
	switch (sess->config->version) {
	case VTLS_TLSVERSION_SSLv3:
		prioritylist = GNUTLS_CIPHERS ":-VERS-TLS-ALL:+VERS-SSL3.0";
		sni = 0;
		break;
	case VTLS_TLSVERSION_TLSv1:
		prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:" GNUTLS_SRP;
		break;
	case VTLS_TLSVERSION_TLSv1_0:
		prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:"
			"+VERS-TLS1.0:" GNUTLS_SRP;
		break;
	case VTLS_TLSVERSION_TLSv1_1:
		prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:"
			"+VERS-TLS1.1:" GNUTLS_SRP;
		break;
	case VTLS_TLSVERSION_TLSv1_2:
		prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:"
			"+VERS-TLS1.2:" GNUTLS_SRP;
		break;
	case VTLS_TLSVERSION_SSLv2:
	default:
		error_printf(conn, "GnuTLS does not support SSLv2\n");
		return CURLE_SSL_CONNECT_ERROR;
		break;
	}
	debug_printf(conn, "priority string %s\n", prioritylist);
	rc = gnutls_priority_set_direct(backend->session, prioritylist, &err);
	if ((rc == GNUTLS_E_INVALID_REQUEST) && err) {
		if (!strcmp(err, GNUTLS_SRP)) {
			/* This GnuTLS was probably compiled without support for SRP.
			 * Note that fact and try again without it. */
			size_t validprioritylen = err - prioritylist;
			char *prioritycopy = strdup(prioritylist);
			if (!prioritycopy)
				return CURLE_OUT_OF_MEMORY;

			error_printf(conn, "This GnuTLS does not support SRP\n");
			if (validprioritylen)
				/* Remove the :+SRP */
				prioritycopy[validprioritylen - 1] = 0;
			rc = gnutls_priority_set_direct(backend->session, prioritycopy, &err);
			free(prioritycopy);
		}
	}
	if (rc != GNUTLS_E_SUCCESS) {
		error_printf(conn, "Error %d setting GnuTLS cipher list starting with %s\n", rc, err);
		return CURLE_SSL_CONNECT_ERROR;
	}
#endif

	if (conn->alpn_count) {
		gnutls_datum_t data[conn->alpn_count];
		unsigned it;

		for (it = 0; it < conn->alpn_count; it++) {
			data[it].data = (unsigned char *)conn->alpn[it];
			data[it].size = strlen(conn->alpn[it]);
			debug_printf(conn, "ALPN offering %s\n", conn->alpn[it]);
		}

		gnutls_alpn_set_protocols(backend->session, data, conn->alpn_count, 0);
	}

	if (sess->config->CERTfile) {
		if (gnutls_certificate_set_x509_key_file(backend->cred,
			sess->config->CERTfile,
			sess->config->KEYfile ? sess->config->KEYfile : sess->config->CERTfile,
			do_file_type(sess->config->cert_type)) != GNUTLS_E_SUCCESS)
		{
			error_printf(conn, "error reading X.509 key or certificate file");
			return CURLE_SSL_CONNECT_ERROR;
		}
	}

#ifdef USE_TLS_SRP
	/* put the credentials to the current session */
	if (data->set.ssl.authtype == CURL_TLSAUTH_SRP) {
		rc = gnutls_credentials_set(backend->session, GNUTLS_CRD_SRP, sess->srp_client_cred);
		if (rc != GNUTLS_E_SUCCESS)
			error_printf(conn, "gnutls_credentials_set() failed: %s", gnutls_strerror(rc));
	} else
#endif
		rc = gnutls_credentials_set(backend->session, GNUTLS_CRD_CERTIFICATE, backend->cred);

	/* set the connection handle (file descriptor for the socket) */
	gnutls_transport_set_ptr(backend->session, GNUTLS_INT_TO_POINTER_CAST(conn->sockfd));

	/* register callback functions to send and receive data. */
	gnutls_transport_set_push_function(backend->session, vtls_push);
	gnutls_transport_set_pull_function(backend->session, vtls_pull);

	/* lowat must be set to zero when using custom push and pull functions. */
//	gnutls_transport_set_lowat(backend->session, 0);

#ifdef HAS_OCSP
	if (sess->config->verifystatus) {
		rc = gnutls_ocsp_status_request_enable_client(backend->session, NULL, 0, NULL);
		if (rc != GNUTLS_E_SUCCESS) {
			error_printf(conn, "gnutls_ocsp_status_request_enable_client() failed: %d", rc);
			return CURLE_SSL_CONNECT_ERROR;
		}
	}
#endif

	/* This might be a reconnect, so we check for a session ID in the cache
		to speed up things */

//	if (!Curl_ssl_getsessionid(sess, &ssl_sessionid, &ssl_idsize)) {
		/* we got a session id, use it! */
//		gnutls_session_set_data(backend->session, ssl_sessionid, ssl_idsize);

		/* Informational message */
//		debug_printf(config, "SSL re-using session ID\n");
//	}

	return 0;
}

static int pkp_pin_peer_pubkey(gnutls_x509_crt_t cert,
	const char *pinnedpubkey)
{
	/* Scratch */
	size_t len1 = 0, len2 = 0;
	unsigned char *buff1 = NULL;

	gnutls_pubkey_t key = NULL;

	/* Result is returned to caller */
	int ret = 0;
	int result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;

	/* if a path wasn't specified, don't pin */
	if (NULL == pinnedpubkey)
		return 0;

	if (NULL == cert)
		return result;

	do {
		/* Begin Gyrations to get the public key     */
		gnutls_pubkey_init(&key);

		ret = gnutls_pubkey_import_x509(key, cert, 0);
		if (ret < 0)
			break; /* failed */

		ret = gnutls_pubkey_export(key, GNUTLS_X509_FMT_DER, NULL, &len1);
		if (ret != GNUTLS_E_SHORT_MEMORY_BUFFER || len1 == 0)
			break; /* failed */

		buff1 = malloc(len1);
		if (NULL == buff1)
			break; /* failed */

		len2 = len1;

		ret = gnutls_pubkey_export(key, GNUTLS_X509_FMT_DER, buff1, &len2);
		if (ret < 0 || len1 != len2)
			break; /* failed */

		/* End Gyrations */

		/* The one good exit point */
//		result = Curl_pin_peer_pubkey(pinnedpubkey, buff1, len1);
	} while (0);

	if (NULL != key)
		gnutls_pubkey_deinit(key);

//	Curl_safefree(buff1);

	return result;
}

static int gtls_connect_step3(vtls_connection_t *conn)
{
	vtls_session_t *sess = conn->session;
	unsigned int cert_list_size;
	const gnutls_datum_t *chainp;
	unsigned int verify_status;
	gnutls_x509_crt_t x509_cert, x509_issuer;
	gnutls_datum_t issuerp;
	char certbuf[256] = ""; /* big enough? */
	size_t size;
	unsigned int algo;
	unsigned int bits;
	time_t certclock;
	const char *ptr;
	struct backend_session_data *backend = sess->backend_data;
	int rc;
//	int incache;
//	void *ssl_sessionid;
#ifdef HAS_ALPN
	gnutls_datum_t proto;
#endif
	int result = 0;

	/* This function will return the peer's raw certificate (chain) as sent by
		the peer. These certificates are in raw format (DER encoded for
		X.509). In case of a X.509 then a certificate list may be present. The
		first certificate in the list is the peer's certificate, following the
		issuer's certificate, then the issuer's issuer etc. */

	chainp = gnutls_certificate_get_peers(backend->session, &cert_list_size);
	debug_printf(conn, "\t cert chain entries: %u\n", cert_list_size);
	if (!chainp) {
		if (sess->config->verifypeer || sess->config->verifyhost || sess->config->issuercert) {
#ifdef USE_TLS_SRP
			if (sess->config->authtype == CURL_TLSAUTH_SRP
				&& sess->config->username != NULL
				&& !sess->config->verifypeer
				&& gnutls_cipher_get(session))
			{
				/* no peer cert, but auth is ok if we have SRP user and cipher and no
					peer verify */
			} else {
#endif
				error_printf(conn, "failed to get server cert\n");
				return CURLE_PEER_FAILED_VERIFICATION;
#ifdef USE_TLS_SRP
			}
#endif
		}
		debug_printf(conn, "\t common name: WARNING couldn't obtain\n");
	}

	if (sess->config->verifypeer) {
		/* This function will try to verify the peer's certificate and return its
			status (trusted, invalid etc.). The value of status should be one or
			more of the gnutls_certificate_status_t enumerated elements bitwise
			or'd. To avoid denial of service attacks some default upper limits
			regarding the certificate key size and chain size are set. To override
			them use gnutls_certificate_set_verify_limits(). */

		rc = gnutls_certificate_verify_peers2(backend->session, &verify_status);
		if (rc < 0) {
			error_printf(conn, "server cert verify failed: %d", rc);
			return CURLE_SSL_CONNECT_ERROR;
		}

		/* verify_status is a bitmask of gnutls_certificate_status bits */
		if (verify_status & GNUTLS_CERT_INVALID) {
			if (sess->config->verifypeer) {
				error_printf(conn, "server certificate verification failed. CAfile: %s "
					"CRLfile: %s\n", sess->config->CAfile ? sess->config->CAfile : "none",
					sess->config->CRLfile ? sess->config->CRLfile : "none");
				return CURLE_SSL_CACERT;
			} else
				debug_printf(conn, "\t server certificate verification FAILED\n");
		} else
			debug_printf(conn, "\t server certificate verification OK\n");
	} else
		debug_printf(conn, "\t server certificate verification SKIPPED\n");

#ifdef HAS_OCSP
	if (sess->config->verifystatus) {
		if (gnutls_ocsp_status_request_is_checked(backend->session, 0) == 0) {
			if (verify_status & GNUTLS_CERT_REVOKED) {
				debug_printf(conn, "\t TLS server certificate was REVOKED\n");
				return CURLE_SSL_INVALIDCERTSTATUS;
			} else
				debug_printf(conn, "\t TLS status verification not supported by server\n");
		} else
			debug_printf(conn, "\t TLS server certificate status verification OK\n");
	} else
		debug_printf(conn, "\t TLS server certificate status verification SKIPPED\n");
#endif

	/* initialize an X.509 certificate structure. */
	gnutls_x509_crt_init(&x509_cert);

	if (chainp)
		/* convert the given DER or PEM encoded Certificate to the native
			gnutls_x509_crt_t format */
		gnutls_x509_crt_import(x509_cert, chainp, GNUTLS_X509_FMT_DER);

	if (sess->config->issuercert) {
		gnutls_x509_crt_init(&x509_issuer);
		issuerp = load_file(sess->config->issuercert);
		gnutls_x509_crt_import(x509_issuer, &issuerp, GNUTLS_X509_FMT_PEM);
		rc = gnutls_x509_crt_check_issuer(x509_cert, x509_issuer);
		gnutls_x509_crt_deinit(x509_issuer);
		unload_file(issuerp);
		if (rc <= 0) {
			error_printf(conn, "server certificate issuer check failed (IssuerCert: %s)\n",
				sess->config->issuercert ? sess->config->issuercert : "none");
			gnutls_x509_crt_deinit(x509_cert);
			return CURLE_SSL_ISSUER_ERROR;
		}
		debug_printf(conn, "\t server certificate issuer check OK (Issuer Cert: %s)\n",
			sess->config->issuercert ? sess->config->issuercert : "none");
	}

	size = sizeof(certbuf);
	rc = gnutls_x509_crt_get_dn_by_oid(x509_cert, GNUTLS_OID_X520_COMMON_NAME,
		0, /* the first and only one */
		0,
		certbuf,
		&size);
	if (rc) {
		error_printf(conn, "error fetching CN from cert:%s\n", gnutls_strerror(rc));
	}

	/* This function will check if the given certificate's subject matches the
		given hostname. This is a basic implementation of the matching described
		in RFC2818 (HTTPS), which takes into account wildcards, and the subject
		alternative name PKIX extension. Returns non zero on success, and zero on
		failure. */
	debug_printf(conn, "\t SNI hostname=%s\n", conn->hostname);
	rc = gnutls_x509_crt_check_hostname(x509_cert, conn->hostname);
#if GNUTLS_VERSION_NUMBER < 0x030306
	/* Before 3.3.6, gnutls_x509_crt_check_hostname() didn't check IP
		addresses. */
	if (!rc) {
#ifdef ENABLE_IPV6
#define use_addr in6_addr
#else
#define use_addr in_addr
#endif
		unsigned char addrbuf[sizeof(struct use_addr)];
		unsigned char certaddr[sizeof(struct use_addr)];
		size_t addrlen = 0, certaddrlen;
		int i;
		int ret = 0;

		if (Curl_inet_pton(AF_INET, conn->hostname, addrbuf) > 0)
			addrlen = 4;
#ifdef ENABLE_IPV6
		else if (Curl_inet_pton(AF_INET6, conn->hostname, addrbuf) > 0)
			addrlen = 16;
#endif

		if (addrlen) {
			for (i = 0;; i++) {
				certaddrlen = sizeof(certaddr);
				ret = gnutls_x509_crt_get_subject_alt_name(x509_cert, i, certaddr, &certaddrlen, NULL);
				/* If this happens, it wasn't an IP address. */
				if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER)
					continue;
				if (ret < 0)
					break;
				if (ret != GNUTLS_SAN_IPADDRESS)
					continue;
				if (certaddrlen == addrlen && !memcmp(addrbuf, certaddr, addrlen)) {
					rc = 1;
					break;
				}
			}
		}
	}
#endif
	if (!rc) {
		if (sess->config->verifyhost) {
			error_printf(conn, "TLS: certificate subject name (%s) does not match target host name '%s'\n",
				certbuf, conn->hostname);
			gnutls_x509_crt_deinit(x509_cert);
			return CURLE_PEER_FAILED_VERIFICATION;
		} else
			debug_printf(conn, "\t common name: %s (does not match '%s')\n",
				certbuf, conn->hostname);
	} else
		debug_printf(conn, "\t common name: %s (matched)\n", certbuf);

	/* Check for time-based validity */
	certclock = gnutls_x509_crt_get_expiration_time(x509_cert);

	if (certclock == (time_t) - 1) {
		if (sess->config->verifypeer) {
			error_printf(conn, "server cert expiration date verify failed\n");
			gnutls_x509_crt_deinit(x509_cert);
			return CURLE_SSL_CONNECT_ERROR;
		} else
			debug_printf(conn, "\t server certificate expiration date verify FAILED\n");
	} else {
		if (certclock < time(NULL)) {
			if (sess->config->verifypeer) {
				error_printf(conn, "server certificate expiration date has passed.\n");
				gnutls_x509_crt_deinit(x509_cert);
				return CURLE_PEER_FAILED_VERIFICATION;
			} else
				debug_printf(conn, "\t server certificate expiration date FAILED\n");
		} else
			debug_printf(conn, "\t server certificate expiration date OK\n");
	}

	certclock = gnutls_x509_crt_get_activation_time(x509_cert);

	if (certclock == (time_t) - 1) {
		if (sess->config->verifypeer) {
			error_printf(conn, "server cert activation date verify failed\n");
			gnutls_x509_crt_deinit(x509_cert);
			return CURLE_SSL_CONNECT_ERROR;
		} else
			debug_printf(conn, "\t server certificate activation date verify FAILED\n");
	} else {
		if (certclock > time(NULL)) {
			if (sess->config->verifypeer) {
				error_printf(conn, "server certificate not activated yet.\n");
				gnutls_x509_crt_deinit(x509_cert);
				return CURLE_PEER_FAILED_VERIFICATION;
			} else
				debug_printf(conn, "\t server certificate activation date FAILED\n");
		} else
			debug_printf(conn, "\t server certificate activation date OK\n");
	}
/*
	ptr = data->set.str[STRING_SSL_PINNEDPUBLICKEY];
	if (ptr) {
		result = pkp_pin_peer_pubkey(x509_cert, ptr);
		if (result != 0) {
			error_printf(conn, "SSL: public key does not match pinned public key!");
			gnutls_x509_crt_deinit(x509_cert);
			return result;
		}
	}
*/

	/* Show:

	- ciphers used
	- subject
	- start date
	- expire date
	- common name
	- issuer

	 */

	/* public key algorithm's parameters */
	algo = gnutls_x509_crt_get_pk_algorithm(x509_cert, &bits);
	debug_printf(conn, "\t certificate public key: %s\n",
		gnutls_pk_algorithm_get_name(algo));

	/* version of the X.509 certificate. */
	debug_printf(conn, "\t certificate version: #%d\n",
		gnutls_x509_crt_get_version(x509_cert));


	size = sizeof(certbuf);
	gnutls_x509_crt_get_dn(x509_cert, certbuf, &size);
	debug_printf(conn, "\t subject: %s\n", certbuf);

	certclock = gnutls_x509_crt_get_activation_time(x509_cert);
	showtime(conn, "start date", certclock);

	certclock = gnutls_x509_crt_get_expiration_time(x509_cert);
	showtime(conn, "expire date", certclock);

	size = sizeof(certbuf);
	gnutls_x509_crt_get_issuer_dn(x509_cert, certbuf, &size);
	debug_printf(conn, "\t issuer: %s\n", certbuf);

	gnutls_x509_crt_deinit(x509_cert);

	/* compression algorithm (if any) */
	ptr = gnutls_compression_get_name(gnutls_compression_get(backend->session));
	/* the *_get_name() says "NULL" if GNUTLS_COMP_NULL is returned */
	debug_printf(conn, "\t compression: %s\n", ptr);

	/* the name of the cipher used. ie 3DES. */
	ptr = gnutls_cipher_get_name(gnutls_cipher_get(backend->session));
	debug_printf(conn, "\t cipher: %s\n", ptr);

	/* the MAC algorithms name. ie SHA1 */
	ptr = gnutls_mac_get_name(gnutls_mac_get(backend->session));
	debug_printf(conn, "\t MAC: %s\n", ptr);

	if (*conn->alpn) {
		gnutls_datum_t proto;

		if ((rc = gnutls_alpn_get_selected_protocol(backend->session, &proto)) == 0) {
			snprintf(conn->alpn_selected, sizeof(conn->alpn_selected), "%.*s", proto.size, proto.data);
			debug_printf(conn, "ALPN protocol selected: %s\n", conn->alpn_selected);
		} else
			error_printf(conn, "No ALPN protocol selected by server\n");
	}

	conn->state = ssl_connection_complete;
//	conn->recv[sockindex] = gtls_recv;
//	conn->send[sockindex] = gtls_send;

#ifdef unsused_code
	{
		/* we always unconditionally get the session id here, as even if we
			already got it from the cache and asked to use it in the connection, it
			might've been rejected and then a new one is in use now and we need to
			detect that. */
		void *connect_sessionid;
		size_t connect_idsize = 0;

		/* get the session ID data size */
		gnutls_session_get_data(session, NULL, &connect_idsize);
		connect_sessionid = malloc(connect_idsize); /* get a buffer for it */

		if (connect_sessionid) {
			/* extract session ID to the allocated buffer */
			gnutls_session_get_data(session, connect_sessionid, &connect_idsize);

			incache = !(Curl_ssl_getsessionid(conn, &ssl_sessionid, NULL));
			if (incache) {
				/* there was one before in the cache, so instead of risking that the
					previous one was rejected, we just kill that and store the new */
				Curl_ssl_delsessionid(conn, ssl_sessionid);
			}

			/* store this session id */
			result = Curl_ssl_addsessionid(conn, connect_sessionid, connect_idsize);
			if (result) {
				free(connect_sessionid);
				result = CURLE_OUT_OF_MEMORY;
			}
		} else
			result = CURLE_OUT_OF_MEMORY;
	}
#endif

	return result;
}


/*
 * This function is called after the TCP connect has completed. Setup the TLS
 * layer and do all necessary magic.
 */

/* We use connssl->connecting_state to keep track of the connection status;
	there are three states: 'ssl_connect_1' (not started yet or complete),
	'ssl_connect_2_reading' (waiting for data from server), and
	'ssl_connect_2_writing' (waiting to be able to write).
 */
static int gtls_connect_common(vtls_connection_t *conn, int nonblocking, int *done)
{
	int rc;

	/* Initiate the connection, if not already done */
	if (ssl_connect_1 == conn->connecting_state) {
		rc = gtls_connect_step1(conn);
		if (rc)
			return rc;
	}

	rc = handshake(conn, nonblocking);
	if (rc)
		/* handshake() sets its own error message with failf() */
		return rc;

	/* Finish connecting once the handshake is done */
	if (ssl_connect_1 == conn->connecting_state) {
		rc = gtls_connect_step3(conn);
		if (rc)
			return rc;
	}

	*done = ssl_connect_1 == conn->connecting_state;

	return 0;
}

int backend_connect(vtls_connection_t *conn)
{
	int result;
	int done = 0;

	result = gtls_connect_common(conn, 1, &done);
	if (result)
		return result;

//	DEBUGASSERT(done);

	return 0;
}

ssize_t backend_write(vtls_connection_t *conn, const void *buf, size_t count)
{
	struct backend_session_data *backend = conn->session->backend_data;
	ssize_t rc;

	int what = Curl_socket_ready(-1, conn->sockfd, conn->write_timeout);
	if (what < 0) {
		/* fatal error */
		debug_printf(conn, "select/poll on SSL socket, errno: %d\n", SOCKERRNO);
		return CURLE_SSL_CONNECT_ERROR;
	} else if (0 == what) {
		if (conn->write_timeout) {
			/* timeout */
			debug_printf(conn, "SSL connection write timeout at %d\n", conn->write_timeout);
			return CURLE_OPERATION_TIMEDOUT;
		}
	}

	rc = gnutls_record_send(backend->session, buf, count);

	if (rc < 0) {
		conn->curlcode = (rc == GNUTLS_E_AGAIN) ? CURLE_AGAIN : CURLE_SEND_ERROR;
		rc = -1;
	}

	return rc;
}

static void close_one(vtls_connection_t *conn)
{
	struct backend_session_data *backend = conn->session->backend_data;

	if (backend->session) {
		gnutls_bye(backend->session, GNUTLS_SHUT_RDWR);
		gnutls_deinit(backend->session);
		backend->session = NULL;
	}
	if (backend->cred) {
		gnutls_certificate_free_credentials(backend->cred);
		backend->cred = NULL;
	}
#ifdef USE_TLS_SRP
	if (backend->srp_client_cred) {
		gnutls_srp_free_client_credentials(backend->srp_client_cred);
		backend->srp_client_cred = NULL;
	}
#endif
}

void backend_close(vtls_connection_t *conn)
{
	close_one(conn);
}

/*
 * This function is called to shut down the SSL layer but keep the
 * socket open (CCC - Clear Command Channel)
 */
int backend_shutdown(vtls_connection_t *conn)
{
	struct backend_session_data *backend = conn->session->backend_data;
//	gnutls_session_t session = backend->session;
	ssize_t result;
	int retval = 0;
//	struct SessionHandle *data = conn->data;
	int done = 0;
	char buf[120];

	/* This has only been tested on the proftpd server, and the mod_tls code
		sends a close notify alert without waiting for a close notify alert in
		response. Thus we wait for a close notify alert from the server, but
		we do not send one. Let's hope other servers do the same... */

//	if (data->set.ftp_ccc == CURLFTPSSL_CCC_ACTIVE)
//		gnutls_bye(sess->ssl_session, GNUTLS_SHUT_WR);

	if (backend->session) {
		while (!done) {
			int what = Curl_socket_ready(conn->sockfd, -1, SSL_SHUTDOWN_TIMEOUT);
			if (what > 0) {
				/* Something to read, let's do it and hope that it is the close
					notify alert from the server */
				result = gnutls_record_recv(backend->session, buf, sizeof(buf));
				switch (result) {
				case 0:
					/* This is the expected response. There was no data but only
						the close notify alert */
					done = 1;
					break;
				case GNUTLS_E_AGAIN:
				case GNUTLS_E_INTERRUPTED:
					debug_printf(conn, "GNUTLS_E_AGAIN || GNUTLS_E_INTERRUPTED\n");
					break;
				default:
					retval = -1;
					done = 1;
					break;
				}
			} else if (0 == what) {
				/* timeout */
				debug_printf(conn, "SSL shutdown timeout\n");
				done = 1;
				break;
			} else {
				/* anything that gets here is fatally bad */
				error_printf(conn, "select/poll on SSL socket, errno: %d\n", SOCKERRNO);
				retval = -1;
				done = 1;
			}
		}
		gnutls_deinit(backend->session);
		backend->session = NULL;
	}

	gnutls_certificate_free_credentials(backend->cred);
	backend->cred = NULL;

#ifdef USE_TLS_SRP
	if (sess->config->authtype == CURL_TLSAUTH_SRP && sess->config->username) {
		gnutls_srp_free_client_credentials(backend->srp_client_cred);
		backend->srp_client_cred = NULL;
	}
#endif

	return retval;
}

ssize_t backend_read(vtls_connection_t *conn,
	char *buf, /* store read data here */
	size_t count) /* max amount to read */
{
	struct backend_session_data *backend = conn->session->backend_data;
	ssize_t ret;

	int what = Curl_socket_ready(conn->sockfd, -1, conn->read_timeout);
	if (what < 0) {
		/* fatal error */
		error_printf(conn, "select/poll on TLS socket, errno: %d", SOCKERRNO);
		return CURLE_SSL_CONNECT_ERROR;
	} else if (0 == what) {
		if (conn->read_timeout) {
			/* timeout */
			error_printf(conn, "TLS connection timeout at %d", conn->read_timeout);
			return CURLE_OPERATION_TIMEDOUT;
		}
	}

	ret = gnutls_record_recv(backend->session, buf, count);
	if ((ret == GNUTLS_E_AGAIN) || (ret == GNUTLS_E_INTERRUPTED)) {
		conn->curlcode = CURLE_AGAIN;
		return -1;
	}

	if (ret == GNUTLS_E_REHANDSHAKE) {
		/* BLOCKING call, this is bad but a work-around for now. Fixing this "the
			proper way" takes a whole lot of work. */
		int result = handshake(conn, 0);
		if (result)
			/* handshake() writes error message on its own */
			conn->curlcode = result;
		else
			conn->curlcode = CURLE_AGAIN; /* then return as if this was a wouldblock */
		return -1;
	}

	if (ret < 0) {
		error_printf(conn, "GnuTLS recv error (%d): %s\n", (int) ret, gnutls_strerror((int) ret));
		conn->curlcode = CURLE_RECV_ERROR;
		return -1;
	}

	return ret;
}

void backend_session_free(void *ptr)
{
	xfree(ptr);
}

size_t backend_version(char *buffer, size_t size)
{
	return snprintf(buffer, size, "GnuTLS/%s", gnutls_check_version(NULL));
}

int backend_md5sum(unsigned char *tmp, /* input */
	size_t tmplen,
	unsigned char *md5sum, /* output */
	size_t md5len)
{
#if defined(USE_GNUTLS_NETTLE)
	struct md5_ctx MD5pw;

	md5_init(&MD5pw);
	md5_update(&MD5pw, (unsigned int) tmplen, tmp);
	md5_digest(&MD5pw, (unsigned int) md5len, md5sum);

	return 0;
#else
	gcry_md_hd_t MD5pw;

	gcry_md_open(&MD5pw, GCRY_MD_MD5, 0);
	gcry_md_write(MD5pw, tmp, tmplen);
	memcpy(md5sum, gcry_md_read(MD5pw, 0), md5len);
	gcry_md_close(MD5pw);

	return 0;
#endif

	return -1;
}

int backend_cert_status_request(void)
{
#ifdef HAS_OCSP
	return 1;
#else
	return 0;
#endif
}
