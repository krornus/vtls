/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* This file is for implementing all "generic" SSL functions that all libcurl
	internals should use. It is then responsible for calling the proper
	"backend" function.

	SSL-functions in libcurl should call functions in this source file, and not
	to any specific SSL-layer.

	vtls_ - prefix for generic ones
	Curl_ossl_ - prefix for OpenSSL ones
	Curl_gtls_ - prefix for GnuTLS ones
	Curl_nss_ - prefix for NSS ones
	Curl_gskit_ - prefix for GSKit ones
	Curl_polarssl_ - prefix for PolarSSL ones
	Curl_cyassl_ - prefix for CyaSSL ones
	Curl_schannel_ - prefix for Schannel SSPI ones
	Curl_darwinssl_ - prefix for SecureTransport (Darwin) ones

	Note that this source code uses curlssl_* functions, and they are all
	defines/macros #defined by the lib-specific header files.

	"SSL/TLS Strong Encryption: An Introduction"
	http://httpd.apache.org/docs-2.0/ssl/ssl_intro.html
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>

// #include "urldata.h"

#include <vtls.h> /* generic SSL protos etc */
#include "common.h"
#include "timeval.h"
#include "backend.h"

/*
#include "slist.h"
#include "sendf.h"
#include "rawstr.h"
#include "url.h"
#include "curl_memory.h"
#include "progress.h"
#include "share.h"
#include "timeval.h"
#include "curl_md5.h"
#include "warnless.h"
#include "curl_base64.h"
 */

#define _MPRINTF_REPLACE /* use our functions only */
// #include <curl/mprintf.h>

/* The last #include file should be: */
// #include "memdebug.h"

/* convenience macro to check if this handle is using a shared SSL session */
#define SSLSESSION_SHARED(data) (data->share &&                        \
                                 (data->share->specifier &             \
                                  (1<<CURL_LOCK_DATA_SSL_SESSION)))

static const vtls_config_t _default_config_static = {
	NULL, /* lock_callback: callback function for multithread library use */
	NULL, /* errormsg_callback: callback function for error messages */
	NULL, /* debugmsg_callback: callback function for debug messages */
	NULL, /* errormsg_ctx: user context for error messages */
	NULL, /* debugmsg_ctx: user context for debug messages */
	NULL, /* CAfile: certificate file or directory to verify peer against */
	NULL, /* CRLfile; CRL to check certificate revocation */
	NULL, /* CERTfile: */
	NULL, /* KEYfile: */
	NULL, /* issuercert: optional issuer certificate filename */
	NULL, /* random_file: path to file containing "random" data */
	NULL, /* egdsocket; path to file containing the EGD daemon socket */
	NULL, /* cipher_list; list of ciphers to use */
	NULL, /* username: TLS username (for, e.g., SRP) */
	NULL, /* password: TLS password (for, e.g., SRP) */
	CURL_TLSAUTH_NONE, /* TLS authentication type (default NONE) */
	VTLS_TLSVERSION_TLSv1_0,	/* version: what TLS version the client wants to use */
	1, /* verifypeer: if peer verification is requested */
	1, /* verifyhost: if hostname matching is requested */
	1, /* verifystatus: if certificate status check is requested */
	0  /* cert_type: filetype of CERTfile and KEYfile */
};
static vtls_config_t *_default_config;

void __attribute__ ((format (printf, 2, 3))) error_printf(vtls_connection_t *conn, const char *fmt, ...)
{
	vtls_error_callback_t func;

	if (conn && conn->session && conn->session->config)
		func = conn->session->config->errormsg_callback;
	else
		func = _default_config->errormsg_callback;

	if (func) {
		va_list args;

		va_start(args, fmt);
		func(conn, fmt, args);
		va_end(args);
	}
}

void __attribute__ ((format (printf, 2, 3))) debug_printf(vtls_connection_t *conn, const char *fmt, ...)
{
	vtls_error_callback_t func;

	if (conn && conn->session)
		func = conn->session->config->debugmsg_callback;
	else
		func = _default_config->debugmsg_callback;

	if (func) {
		va_list args;

		va_start(args, fmt);
		func(conn, fmt, args);
		va_end(args);
	}
}

/*
#define FETCH_AND_DUP(s) \
	if (((*config)->s = va_arg(args, const char *))) {\
		(*config)->s = strdup((*config)->s);\
		if (!(*config)->s)\
			return -2;\
	}
int vtls_config_init(vtls_config_t **config, ...)
{
	va_list args;
	int key;

	if (!config)
		return -1;

	if (!(*config = malloc(sizeof(**config))))
		return -2;

	// copy default values
	memcpy(*config, &_default_config_static, sizeof(_default_config_static));

	va_start(args, config);
	for (key = va_arg(args, int); key; key = va_arg(args, int)) {
		switch (key) {
		case VTLS_CFG_TLS_VERSION:
			(*config)->version = va_arg(args, int);
			break;
		case VTLS_CFG_VERIFY_PEER:
			(*config)->verifypeer = va_arg(args, int);
			break;
		case VTLS_CFG_VERIFY_HOST:
			(*config)->verifyhost = va_arg(args, int);
			break;
		case VTLS_CFG_VERIFY_STATUS:
			(*config)->verifystatus = va_arg(args, int);
			break;
		case VTLS_CFG_CA_FILE:
			FETCH_AND_DUP(CAfile);
			break;
		case VTLS_CFG_CRL_FILE:
			FETCH_AND_DUP(CRLfile);
			break;
		case VTLS_CFG_ISSUER_FILE:
			FETCH_AND_DUP(issuercert);
			break;
		case VTLS_CFG_RANDOM_FILE:
			FETCH_AND_DUP(random_file);
			break;
		case VTLS_CFG_EGD_SOCKET:
			FETCH_AND_DUP(egdsocket);
			break;
		case VTLS_CFG_CIPHER_LIST:
			FETCH_AND_DUP(cipher_list);
			break;
		case VTLS_CFG_LOCK_CALLBACK:
			(*config)->lock_callback = va_arg(args, void(*)(int));
			break;
		case VTLS_CFG_ERRORMSG_CALLBACK:
			(*config)->errormsg_callback = va_arg(args, vtls_debug_callback_t);
			(*config)->errormsg_ctx = va_arg(args, void *);
			break;
		case VTLS_CFG_DEBUGMSG_CALLBACK:
			(*config)->debugmsg_callback = va_arg(args, vtls_debug_callback_t);
			(*config)->debugmsg_ctx = va_arg(args, void *);
			break;
		case VTLS_CFG_CONNECT_TIMEOUT:
			(*config)->connect_timeout = va_arg(args, int);
			break;
		case VTLS_CFG_READ_TIMEOUT:
			(*config)->read_timeout = va_arg(args, int);
			break;
		case VTLS_CFG_WRITE_TIMEOUT:
			(*config)->write_timeout = va_arg(args, int);
			break;
		default:
			// unknown key
			if ((*config)->errormsg_callback)
				error_printf(*config, "Unknown key %d\n", key);
			else if (_default_config->errormsg_callback)
				error_printf(_default_config, "Unknown key %d\n", key);
			vtls_config_deinit(*config);
			return -3;
		}
	}
	va_end(args);

	return 0;
}
#undef FETCH_AND_DUP
*/

int vtls_config_matches(const vtls_config_t *data, const vtls_config_t *needle)
{
	return ((data->version == needle->version) &&
		(data->verifypeer == needle->verifypeer) &&
		(data->verifyhost == needle->verifyhost) &&
		(data->verifystatus == needle->verifystatus) &&
		vtls_strcaseequal_ascii(data->CAfile, needle->CAfile) &&
		vtls_strcaseequal_ascii(data->CRLfile, needle->CRLfile) &&
		vtls_strcaseequal_ascii(data->CERTfile, needle->CERTfile) &&
		vtls_strcaseequal_ascii(data->KEYfile, needle->KEYfile) &&
		vtls_strcaseequal_ascii(data->issuercert, needle->issuercert) &&
		vtls_strcaseequal_ascii(data->random_file, needle->random_file) &&
		vtls_strcaseequal_ascii(data->egdsocket, needle->egdsocket) &&
		vtls_strcaseequal_ascii(data->cipher_list, needle->cipher_list));
}

#define DUP_MEMBER(s) \
	if (src->s) {\
		(*dst)->s = strdup(src->s);\
		if (!(*dst)->s)\
			return -2;\
	}

int vtls_config_clone(const vtls_config_t *src, vtls_config_t **dst)
{
	if (!dst)
		return -1;

	if (!(*dst = calloc(1, sizeof(**dst))))
		return -2;

	// copy config values
	memcpy(*dst, src, sizeof(*src));

	/* and dup the strings */
	DUP_MEMBER(CAfile);
	DUP_MEMBER(CRLfile);
	DUP_MEMBER(issuercert);
	DUP_MEMBER(random_file);
	DUP_MEMBER(egdsocket);
	DUP_MEMBER(cipher_list);

	return 0;
}
#undef DUP_MEMBER

void vtls_config_deinit(vtls_config_t *config)
{
	if (!config)
		return;

	xfree(config->CAfile);
	xfree(config->CRLfile);
	xfree(config->CERTfile);
	xfree(config->KEYfile);
	xfree(config->cipher_list);
	xfree(config->egdsocket);
	xfree(config->random_file);
	xfree(config->username);
	xfree(config->password);
	xfree(config);
}

vtls_debug_callback_t _debugmsg_callback;
void vtls_glob_set_debug_callback(vtls_debug_callback_t func) {
	_debugmsg_callback = func;
}

vtls_debug_callback_t _errormsg_callback;
void vtls_glob_set_error_callback(vtls_error_callback_t func) {
	_errormsg_callback = func;
}

vtls_lock_callback_t _lock_callback;
void vtls_glob_set_lock_callback(vtls_lock_callback_t func) {
	_lock_callback = func;
}

int vtls_get_engine(void)
{
	return backend_get_engine();
}

/* "global" init done? */
static int _init_vtls = 0;

/**
 * Global SSL init
 *
 * @retval 0 SSL initialized successfully
 * @retval 1 error initializing SSL
 */
int vtls_init(void)
{
	int ret = -1;

	if (_lock_callback)
		_lock_callback(1);

	/* make sure this is only done once */
	if (_init_vtls++ == 0) {
		if ((ret = vtls_config_clone(&_default_config_static, &_default_config)) == 0) {
			_default_config->errormsg_callback = _errormsg_callback;
			_default_config->debugmsg_callback = _debugmsg_callback;
			_default_config->lock_callback = _lock_callback;

			if ((ret = backend_init()) != 0) {
				vtls_config_deinit(_default_config);
				_default_config = NULL;
				_init_vtls = 0;
			}
		}
	}

	if (_lock_callback)
		_lock_callback(0);

	return ret;
}

/* Global cleanup */
void vtls_deinit(void)
{
	if (_lock_callback)
		_lock_callback(1);

	if (_init_vtls && --_init_vtls == 0) {
		/* only the last deinit() does the job */
		backend_deinit();
		vtls_config_deinit(_default_config);
		_default_config = NULL;
	}

	if (_lock_callback)
		_lock_callback(0);
}

int vtls_session_init(vtls_session_t **sess)
{
	int ret;

	if (!sess)
		return -1;

	if (!(*sess = calloc(1, sizeof(**sess))))
		return -2;

	vtls_config_clone(_default_config, &(*sess)->config);

	if ((ret = backend_session_init(*sess)))
		vtls_session_deinit(*sess);

	return ret;
}

void vtls_session_deinit(vtls_session_t *sess)
{
	backend_session_deinit(sess);
	vtls_config_deinit(sess->config);
	xfree(sess);
}

int vtls_set_debug_callback(vtls_session_t *sess, vtls_debug_callback_t func, void *ctx)
{
	if (!sess)
		return -1;

	sess->config->debugmsg_callback = func;
	sess->config->debugmsg_ctx = ctx;
	return 0;
}

int vtls_set_error_callback(vtls_session_t *sess, vtls_error_callback_t func, void *ctx)
{
	if (!sess)
		return -1;

	sess->config->errormsg_callback = func;
	sess->config->errormsg_ctx = ctx;
	return 0;
}

int vtls_set_lock_callback(vtls_session_t *sess, vtls_lock_callback_t func)
{
	if (!sess)
		return -1;

	sess->config->lock_callback = func;
	return 0;
}

int vtls_set_tls_version(vtls_session_t *sess, enum vtls_tls_version version)
{
	if (sess) {
		if (version >= VTLS_TLSVERSION_SSLv2 && version < VTLS_TLSVERSION_LAST) {
			sess->config->version = version;
			return 0;
		}
	}

	return -1;
}

int vtls_set_ca_file(vtls_session_t *sess, const char *ca_file)
{
	if (sess) {
		if (sess->config)
			xfree(sess->config->CAfile);

		if ((sess->config->CAfile = strdup(ca_file)))
			return 0;
	}

	return -1;
}

int vtls_conn_set_sni_hostname(vtls_connection_t *conn, const char *hostname)
{
	if (conn) {
		if (conn->hostname)
			xfree(conn->hostname);

		if ((conn->hostname = strdup(hostname)))
			return 0;
	}

	return -1;
}

int vtls_conn_set_protocol(vtls_connection_t *conn, const char *protocol)
{
	if (!conn || !protocol)
		return -1;

	if (conn->alpn_count >= sizeof(conn->alpn)/sizeof(conn->alpn[0]))
		return -1;

	snprintf(conn->alpn[conn->alpn_count++], sizeof(conn->alpn[0]), "%s", protocol);
	return 0;
}

int vtls_conn_get_protocol(vtls_connection_t *conn, char *protocol, size_t protocol_size)
{
	if (!conn || !protocol || !protocol_size)
		return -1;

	snprintf(protocol, protocol_size, "%s", conn->alpn_selected);

	if (!*protocol)
		return -1;

	return 0;
}

int vtls_get_status_code(vtls_connection_t *conn)
{
	return conn ? conn->curlcode : -1;
}

int vtls_connection_init(vtls_connection_t **conn, vtls_session_t *sess, int sockfd)
{
	if (!conn)
		return -1;

	if (!(*conn = calloc(1, sizeof(**conn))))
		return -2;

	(*conn)->session = sess;
	(*conn)->sockfd = sockfd;

	/* default settings */
	(*conn)->connect_timeout = 30*1000;
	(*conn)->read_timeout = 10*1000;
	(*conn)->write_timeout = 10*1000;
	return 0;
}

void vtls_connection_deinit(vtls_connection_t *conn)
{
}

int vtls_connect(vtls_connection_t *conn)
{
	/* mark this is being TLS-enabled from here on. */
	conn->use = 1;
	conn->state = ssl_connection_negotiating;
	conn->connect_start = curlx_tvnow();

	return backend_connect(conn);
}

ssize_t vtls_write(vtls_connection_t *conn, const void *buf, size_t count)
{
	conn->write_start = curlx_tvnow();
	return backend_write(conn, buf, count);
}

ssize_t vtls_read(vtls_connection_t *conn, void *buf, size_t count)
{
	conn->read_start = curlx_tvnow();
	return backend_read(conn, buf, count);
}

void vtls_close(vtls_connection_t *conn)
{
	backend_close(conn);
}

int vtls_shutdown(vtls_connection_t *conn)
{
	if (backend_shutdown(conn))
		return CURLE_SSL_SHUTDOWN_FAILED;

	conn->use = 0;
	conn->state = ssl_connection_none;

	return 0;
}

size_t vtls_version(char *buffer, size_t size)
{
	return backend_version(buffer, size);
}

int vtls_md5sum(unsigned char *tmp, /* input */
	size_t tmplen,
	unsigned char *md5sum, /* output */
	size_t md5len)
{
	int ret;

	if ((ret = backend_md5sum(tmp, tmplen, md5sum, md5len))) {
/*		MD5_context *MD5pw;

		MD5pw = Curl_MD5_init(Curl_DIGEST_MD5);
		Curl_MD5_update(MD5pw, tmp, curlx_uztoui(tmplen));
		Curl_MD5_final(MD5pw, md5sum);
 */
	}

	return ret;
}

/*
 * Check whether the SSL backend supports the status_request extension.
 */
int vtls_cert_status_request(void)
{
	return backend_cert_status_request();
}
