/* 

   This file is part of the University of Cambridge Web Authentication 
   System Application Agent for Apache 1.3 and 2
   See http://raven.cam.ac.uk/ for more details

   Copyright (c) University of Cambridge 2004,2005

   This application agent is free software; you can redistribute it
   and/or modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The agent is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
  
   You should have received a copy of the GNU Lesser General Public
   License along with this toolkit; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
   USA

   $Id: mod_ucam_webauth.c,v 1.72 2009-12-22 15:07:13 jw35 Exp $

   Author: Robin Brady-Roche <rbr268@cam.ac.uk> and 
           Jon Warbrick <jw35@cam.ac.uk>

*/

#define VERSION "1.4.2.bjh21.2"

/*
MODULE-DEFINITION-START
Name: ucam_webauth_module
ConfigStart
  LIBS="$LIBS -lcrypto"
  echo " + using -lcrypto to include OpenSSL library"
ConfigEnd
MODULE-DEFINITION-END
*/

#include <string.h>
#include <time.h>
#ifndef WIN32
#include <strings.h>
#endif

#define CORE_PRIVATE   /* Er, we want to prod some core data structures */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_config.h"

#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#if defined APACHE_RELEASE && APACHE_RELEASE < 20000000
#define APACHE1_3
#endif

#ifdef APACHE1_3
#include "util_date.h"
#include "fnmatch.h"
#else
#include "http_connection.h"
#include "http_config.h"
#include "apr_strings.h"
#include "apr_fnmatch.h"
#include "apr_general.h"
#include "apr_base64.h"
#include "apr_date.h"
#include "apr_uri.h"
#endif

#define PROTOCOL_VERSION "1"
#define AUTH_TYPE1 "webauth"
#define AUTH_TYPE2 "ucam-webauth"
#define TESTSTRING "Not-authenticated"

#define CC_OFF      0
#define CC_ON       1
#define CC_PARANOID 2

#define HDR_NONE        0
#define HDR_ISSUE       1
#define HDR_LAST        2
#define HDR_LIFE        4
#define HDR_TIMEOUT     8
#define HDR_ID         16
#define HDR_PRINCIPAL  32
#define HDR_AUTH       64
#define HDR_SSO       128
#define HDR_ALL       (HDR_NONE | HDR_ISSUE | HDR_LAST | HDR_LIFE \
    | HDR_TIMEOUT | HDR_ID | HDR_PRINCIPAL | HDR_AUTH | HDR_SSO)

/* default parameters */

#define DEFAULT_auth_service     \
  "https://raven.cam.ac.uk/auth/authenticate.html"
#define DEFAULT_logout_service   \
  "https://raven.cam.ac.uk/auth/logout.html"
#define DEFAULT_description        NULL
#define DEFAULT_response_timeout   30
#define DEFAULT_clock_skew         0
#define DEFAULT_key_dir            "conf/webauth_keys"
#define DEFAULT_max_session_life   7200
#define DEFAULT_inactive_timeout   0
#define DEFAULT_timeout_msg        "your session on the site has expired"
#define DEFAULT_cache_control      CC_ON
#define DEFAULT_cookie_key         NULL
#define DEFAULT_cookie_name        "Ucam-WebAuth-Session"
#define DEFAULT_cookie_path        "/"
#define DEFAULT_cookie_domain      NULL
#define DEFAULT_force_interact     0
#define DEFAULT_refuse_interact    0
#define DEFAULT_fail               0
#define DEFAULT_ign_response_life  0
#define DEFAULT_cancel_msg         NULL
#define DEFAULT_need_interact_msg  NULL
#define DEFAULT_no_cookie_msg      NULL
#define DEFAULT_logout_msg         NULL
#define DEFAULT_always_decode      0
#define DEFAULT_headers            HDR_NONE
#define DEFAULT_header_key         NULL
#define DEFAULT_force_auth_type    "Ucam-WebAuth"

/* module configuration structure */

typedef struct {
  char *auth_service;
  char *logout_service;
  char *description;
  int   response_timeout;
  int   clock_skew;
  char *key_dir;
  int   max_session_life;
  int   inactive_timeout;
  char *timeout_msg;
  int   cache_control;
  char *cookie_key;
  char *cookie_name;
  char *cookie_path;
  char *cookie_domain;
  int   force_interact;
  int   refuse_interact;
  int   fail;
  int   ign_response_life;
  char *cancel_msg;
  char *need_interact_msg;
  char *no_cookie_msg;
  char *logout_msg;
  int   always_decode;
  int   headers;
  char *header_key;
  char *force_auth_type;
} mod_ucam_webauth_cfg;

/* logging macro. Note that it will only work in an environment where
   'r' holds a copy of the current request record */

#ifdef APACHE1_3
#define APACHE_LOG0(level, fmt) \
  ap_log_rerror(APLOG_MARK, level | APLOG_NOERRNO, r, fmt)
#define APACHE_LOG1(level, fmt, a) \
  ap_log_rerror(APLOG_MARK, level | APLOG_NOERRNO, r, fmt, a)
#define APACHE_LOG2(level, fmt, a, b) \
  ap_log_rerror(APLOG_MARK, level | APLOG_NOERRNO, r, fmt, a, b)
#define APACHE_LOG3(level, fmt, a, b, c) \
  ap_log_rerror(APLOG_MARK, level | APLOG_NOERRNO, r, fmt, a, b, c)
#define APACHE_LOG4(level, fmt, a, b, c, d) \
  ap_log_rerror(APLOG_MARK, level | APLOG_NOERRNO, r, fmt, a, b, c, d)
#else
#define APACHE_LOG0(level, fmt) \
  ap_log_rerror(APLOG_MARK, level, 0, r, fmt)
#define APACHE_LOG1(level, fmt, a) \
  ap_log_rerror(APLOG_MARK, level, 0, r, fmt, a)
#define APACHE_LOG2(level, fmt, a, b) \
  ap_log_rerror(APLOG_MARK, level, 0, r, fmt, a, b)
#define APACHE_LOG3(level, fmt, a, b, c) \
  ap_log_rerror(APLOG_MARK, level, 0, r, fmt, a, b, c)
#define APACHE_LOG4(level, fmt, a, b, c, d) \
  ap_log_rerror(APLOG_MARK, level, 0, r, fmt, a, b, c, d)
#endif

/* ---------------------------------------------------------------------- */

/* Almost all of the code is written as for Apache 2. The folowing
   macros adapt it for Apache 1.3 if necessary */

#ifdef APACHE1_3

/* types */

#define apr_table_t table
#define apr_time_t time_t
#define apr_pool_t pool
#define apr_uri_t uri_components

/* functions */

#define apr_base64_decode ap_base64decode
#define apr_base64_decode_len ap_base64decode_len
#define apr_base64_encode ap_base64encode
#define apr_base64_encode_len ap_base64encode_len
#define apr_date_parse_http ap_parseHTTPdate
#define apr_fnmatch ap_fnmatch
#define apr_palloc ap_palloc
#define apr_pcalloc ap_pcalloc
#define apr_psprintf ap_psprintf
#define apr_pstrcat ap_pstrcat
#define apr_pstrdup ap_pstrdup
#define apr_table_add ap_table_add
#define apr_table_get ap_table_get
#define apr_table_make ap_make_table
#define apr_table_set ap_table_set
#define apr_table_unset ap_table_unset
#define apr_time_sec(sec) sec
#define apr_time_from_sec(sec) sec
#define apr_uri_parse ap_parse_uri_components
#define apr_uri_unparse ap_unparse_uri_components
#define apr_time_now() time(NULL)

/* other definitions */

#define AP_MODULE_DECLARE_DATA MODULE_VAR_EXPORT
#define APR_OFFSETOF XtOffsetOf
#define APR_FNM_NOMATCH FNM_NOMATCH

#define AP_INIT_TAKE1(name, func, data, override, errmsg) \
  {name, func, data, override, TAKE1, errmsg}
#define AP_INIT_FLAG(name, func, data, override, errmsg) \
  {name, func, data, override, FLAG, errmsg}
#define AP_INIT_RAW_ARGS(name, func, data, override, errmsg) \
  {name, func, data, override, RAW_ARGS, errmsg}

#endif

/* ---------------------------------------------------------------------- */

/* Standard forward declaration of the module structure since
   _something_ is bound to need it before it's defined at the end */

module AP_MODULE_DECLARE_DATA ucam_webauth_module;

/* Utility routines */

/* --- */
/* return a new string that is 'from' with all url-unsafe characters
   converted to escapes. Note that Apache's ap_unescape_url doesn't
   seem to decode '+' into space so we don't use that encoding here
   either */

static char *
escape_url(apr_pool_t *p,
	   const char *from)

{

  static char safechars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "01234567890-_.!~*'()";

  char *to = (char*)apr_pcalloc(p,(strlen(from)*3)+1);
  char *ptr;
  
  ptr = to;

  while (*from != '\0') {
    if (strchr(safechars,*from)) {
      *(ptr++) = *from; 
    }
    else {
      sprintf(ptr, "%%%02x", (int)*from);
      ptr+=3;
    }
    ++from;
  }
  *ptr = '\0';

  return to;
}

/* --- */

static char *
escape_sig(apr_pool_t *p,
	   const char *from)

{

  char *to = (char*)apr_pcalloc(p,(strlen(from)*3)+1);
  char *ptr;
  
  ptr = to;

  while (*from != '\0') {
    if (*from == '%' || *from == '!') {
      sprintf(ptr, "%%%02x", (int)*from);
      ptr+=3;
    }
    else {
      *(ptr++) = *from; 
    }
    ++from;
  }
  *ptr = '\0';

  return to;
}

/* --- */
/* modified base64 encoding */

/* You'd expect that this routing (and wls_decode) could use
   ap_pbase64encode/ap_pbase64encode to do their work, but I don't see
   how you can handle the raw data as a C string (with no explicit length
   indication) which is what these do. So do it by hand... */

static char *
wls_encode(request_rec *r, 
	   unsigned char *data,
           int len) 

{

  int rlen, i;

  char *result = (char*)apr_palloc(r->pool, 1+apr_base64_encode_len(len));
  rlen = apr_base64_encode(result,(const char*)data,len);
  result[rlen] = '\0';
  
  for (i = 0; i < rlen; i++) {
    if (result[i] == '+') result[i] = '-';
    else if (result[i] == '/') result[i] = '.';
    else if (result[i] == '=') result[i] = '_';
  }
  
  return result;

}

/* --- */
/* modified base64 decoding */

static int
wls_decode(request_rec *r, 
	   char *string,
	   unsigned char **result)
     
{

  int len, i;  
  char *d, *res;

  APACHE_LOG0(APLOG_DEBUG, "wls_decode...");

  d = apr_pstrdup(r->pool, string);

  for (i = 0; i < strlen(d); i++) {
    if (d[i] == '-') d[i] = '+';
    else if (d[i] == '.') d[i] = '/';
    else if (d[i] == '_') d[i] = '=';
  }

  res = (char*)apr_palloc(r->pool, 1+apr_base64_decode_len(d));
  len = apr_base64_decode(res, d);

  res[len] = '\0'; /* for safety if nothing else */

  *result = (unsigned char *)res;
  return len;

}

/* --- */
/* ISO 2 datetime encoding */

static char *
iso2_time_encode(request_rec *r, 
		 apr_time_t t) 

{
  
  APACHE_LOG0(APLOG_DEBUG, "ISO 2 time encoding...");
  return ap_ht_time(r->pool, t, "%Y%m%dT%H%M%SZ", 1);

}

/* --- */
/* ISO 2 datetime decoding */

static apr_time_t 
iso2_time_decode(request_rec *r, 
				    char *t_iso2) 

{
  
  char *t_http = (char*)apr_palloc(r->pool, 27);

  APACHE_LOG0(APLOG_DEBUG, "iso2_time_decode...");

  if (strlen(t_iso2) < 16) return -1;
  t_http[0] = ',';
  t_http[1] = ' ';
  /* day */
  t_http[2] = t_iso2[6];
  t_http[3] = t_iso2[7];
  t_http[4] = ' ';
  /* month */
  if (t_iso2[4] == '0') {
    switch (t_iso2[5]) {
    case '1':
      t_http[5] = 'J';
      t_http[6] = 'a'; 
      t_http[7] = 'n';
      break;
    case '2':
      t_http[5] = 'F';
      t_http[6] = 'e';
      t_http[7] = 'b';
      break;
    case '3':
      t_http[5] = 'M';
      t_http[6] = 'a';
      t_http[7] = 'r';
      break;
    case '4':
      t_http[5] = 'A';
      t_http[6] = 'p';
      t_http[7] = 'r';
      break;
    case '5':
      t_http[5] = 'M';
      t_http[6] = 'a';
      t_http[7] = 'y';
      break;
    case '6':
      t_http[5] = 'J';
      t_http[6] = 'u';
      t_http[7] = 'n';
      break;
    case '7':
      t_http[5] = 'J';
      t_http[6] = 'u';
      t_http[7] = 'l';
      break;
    case '8':
      t_http[5] = 'A';
      t_http[6] = 'u';
      t_http[7] = 'g';
      break;
    case '9':
      t_http[5] = 'S';
      t_http[6] = 'e';
      t_http[7] = 'p';
      break;
    }
  } else {
    switch (t_iso2[5]) {
    case '0':
      t_http[5] = 'O';
      t_http[6] = 'c';
      t_http[7] = 't';
      break;
    case '1':
      t_http[5] = 'N';
      t_http[6] = 'o';
      t_http[7] = 'v';
      break;
    case '2':
      t_http[5] = 'D';
      t_http[6] = 'e';
      t_http[7] = 'c';
      break;
    }
  }
  t_http[8] = ' ';
  /* year */
  t_http[9] = t_iso2[0];
  t_http[10] = t_iso2[1];
  t_http[11] = t_iso2[2];
  t_http[12] = t_iso2[3];
  t_http[13] = ' ';
  /* time */
  t_http[14] = t_iso2[9];
  t_http[15] = t_iso2[10];
  t_http[16] = ':';
  t_http[17] = t_iso2[11];
  t_http[18] = t_iso2[12];
  t_http[19] = ':';
  t_http[20] = t_iso2[13];
  t_http[21] = t_iso2[14];
  t_http[22] = ' ';
  t_http[23] = 'G';
  t_http[24] = 'M';
  t_http[25] = 'T';
  t_http[26] = '\0';

  APACHE_LOG1(APLOG_DEBUG, "HTTP date = %s", t_http);
  
  return apr_date_parse_http(t_http);

}

/* --- */
/* Get current customised response definition, if any */
/* 'Borrowed' from the Apache source, informed by the mod_perl sources */

static char *
wls_response_code_string(request_rec *r, 
			 int status)

{
  core_dir_config *conf;
  char *result;
  int idx;
  
  APACHE_LOG1(APLOG_DEBUG, "wls_response_code_string: status = %d", status);

  conf = (core_dir_config *)ap_get_module_config(r->per_dir_config,
						 &core_module);
  idx = ap_index_of_response(status);

  if (conf->response_code_strings == NULL) {
    result = NULL;
  } else {
    result = conf->response_code_strings[idx];
  }

  APACHE_LOG1(APLOG_DEBUG, "wls_response_code_string: result = %s", 
		   (result == NULL ? "NULL" : result));  

  return result;

}
 
/* --- */
/* get CGI parameter */

static char *
get_cgi_param(request_rec *r, 
	      char *parm_name) 

{

  /* note that we use the copy of args saved in the post_read_request
     handler since r->rags can get overriten. note that
     post_read_request isn't run for sub-requests, but that should be
     OK becasue we are always called with r pointing to a main
     request */

  const char *data = apr_table_get(r->notes, "AA_orig_args");
  const char *pair;

  APACHE_LOG1(APLOG_DEBUG, "get_cgi_param, r->args = %s", data);
  
  if (data != NULL) {
    while (*data && (pair = ap_getword(r->pool, &data, '&'))) {
      const char *name;
      name = ap_getword(r->pool, &pair, '=');
      
      if (strcmp(name, parm_name) == 0) {
	return (char *)pair;
      }
    }
  }
  return NULL;

}

/* --- */

static int 
using_https(request_rec *r) 

{

  return (apr_fnmatch("https*", 
			 ap_construct_url(r->pool, r->unparsed_uri, r), 
			 0) != APR_FNM_NOMATCH);

}

/* --- */

static char *
full_cookie_name(request_rec *r, 
		 char *cookie_name) 

{

  char *name = (char *)apr_pstrdup(r->pool, cookie_name);
  int https = using_https(r);
  int port = r->server->port;
  
  if (port > 0 && 
      ((https && port != 443) || (!https && port != 80))) {
    name = apr_psprintf(r->pool,"%s-%d",name,port);
  }

  if (using_https(r)) {
    name = apr_pstrcat(r->pool, cookie_name, "-S", NULL);
  }

  return name;

}

/* --- */
/* set cookie */

static void 
set_cookie(request_rec *r, 
	   char *value, 
	   mod_ucam_webauth_cfg *c) 

{

  char *cookie;

  /* if NULL value supplied then delete cookie by setting expiry in
     the past */

  if (value == NULL) {
    cookie = apr_pstrcat(r->pool, 
			 full_cookie_name(r, c->cookie_name),
			 "= ; path=",
			 c->cookie_path, 
			 "; expires=Thu, 21-Oct-1982 00:00:00 GMT", NULL);
  } else {
    cookie = apr_pstrcat(r->pool, 
			 full_cookie_name(r, c->cookie_name), 
			 "=", escape_url(r->pool,value),
			 "; path=", 
			 c->cookie_path, NULL);
  }
  
  if (c->cookie_domain != NULL) {
    cookie = apr_pstrcat(r->pool, 
			 cookie, 
			 "; domain=", 
			 c->cookie_domain, NULL);
  }
  
  if (using_https(r)) {
    cookie = apr_pstrcat(r->pool, cookie, "; secure", NULL);
  }
  
  APACHE_LOG1(APLOG_DEBUG, "set_cookie: str = %s", cookie);
  
  /* We want this cookie set for error- and non-error responses, hence
     add it to err_headers_out */
  
  apr_table_add(r->err_headers_out, "Set-Cookie", cookie);
  
}

/* --- */
/* log_openssl_errors */

static void
log_openssl_errors(request_rec *r,
		   int level)

{

  int code;
  char msg[120];

  ERR_load_crypto_strings();

  while ((code = ERR_get_error())) {
    (void)ERR_error_string_n(code, &msg[0], 120);
    APACHE_LOG1(level, "  OpenSSL %s", msg);
  }

}

/* --- */
/* SHA1 sign */

static char *
SHA1_sign(request_rec *r, 
	  mod_ucam_webauth_cfg *c,  
	  char *data) 

{

  unsigned char *new_sig = 
    (unsigned char *)apr_pcalloc(r->pool, EVP_MAX_MD_SIZE + 1);
  unsigned int sig_len;

  APACHE_LOG1(APLOG_DEBUG, "making sig with data = %s", data);

  HMAC(EVP_sha1(), c->cookie_key, strlen(c->cookie_key), 
       (const unsigned char *)data, strlen(data), new_sig, &sig_len);
  new_sig = (unsigned char*)wls_encode(r, new_sig, sig_len);

  APACHE_LOG1(APLOG_DEBUG, "new sig = %s", new_sig);

 return (char *)new_sig;

}

/* --- */
/* SHA1 verify */

static int 
SHA1_sig_verify(request_rec *r, 
		mod_ucam_webauth_cfg *c,  
		char *data, 
		const char *sig) 

{

  unsigned char *new_sig = 
    (unsigned char *)apr_pcalloc(r->pool, EVP_MAX_MD_SIZE + 1);
  unsigned int sig_len;

  APACHE_LOG1(APLOG_DEBUG, "verifying sig: %s", sig);
  APACHE_LOG1(APLOG_DEBUG, "on data: %s", data);

  HMAC(EVP_sha1(), c->cookie_key, strlen(c->cookie_key), 
       (const unsigned char *)data, strlen(data), new_sig, &sig_len);
  new_sig = (unsigned char*)wls_encode(r, new_sig, sig_len);

  APACHE_LOG1(APLOG_DEBUG, "new sig = %s", new_sig);

  if (strcmp(sig, (const char *)new_sig) == 0) return 1;
  return 0;

}


/* --- */
/* RSA verify */

static int 
RSA_sig_verify(request_rec *r, 
	       char *data, 
	       char *sig, 
	       char *key_path, 
	       char *key_id) 

{

  unsigned char* decoded_sig;
  int sig_length;
  int result;
  char *key_full_path;
  FILE *key_file;
  char *digest = apr_palloc(r->pool, 21);
  RSA *public_key;

  APACHE_LOG0(APLOG_DEBUG, "RSA_sig_verify...");
  APACHE_LOG1(APLOG_DEBUG, "key_path: %s", key_path);

  key_full_path = 
    ap_make_full_path(r->pool, 
		      key_path, 
		      apr_pstrcat(r->pool, "pubkey", key_id, NULL));

  SHA1((const unsigned char *)data, strlen(data), (unsigned char *)digest);
  
  key_file = (FILE *)fopen(key_full_path, "r");

  if (key_file == NULL) {
    APACHE_LOG2(APLOG_CRIT, "Error opening public key file %s: %s", 
		     key_full_path, strerror(errno));
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  public_key = (RSA *)PEM_read_RSAPublicKey(key_file, NULL, NULL, NULL);

  fclose(key_file);
 
  if (public_key == NULL) {
    APACHE_LOG1
      (APLOG_CRIT, "Error reading public key from %s "
       "(additional information may follow)", key_full_path);
    log_openssl_errors(r,APLOG_CRIT);
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  sig_length = wls_decode(r, sig, &decoded_sig);

  APACHE_LOG1(APLOG_DEBUG, "digest length = %lu", 
              (unsigned long)strlen(digest));
  APACHE_LOG1(APLOG_DEBUG, "sig length = %d", sig_length);

  result = RSA_verify(NID_sha1, 
		      (unsigned char *)digest, 
		      20, 
		      decoded_sig, 
		      sig_length, 
		      public_key);

  APACHE_LOG1(APLOG_DEBUG, "RSA verify result = %d", result);

  if (result != 1) {
    APACHE_LOG0(APLOG_CRIT, 
		"Error validating WLS response signature "
		"(aditional information may follow)");
    log_openssl_errors(r,APLOG_CRIT);
  }

  RSA_free(public_key);
  
  return (result == 1 ? OK : HTTP_BAD_REQUEST);

}

/* --- */

static char *
cookie_check_sig_string(request_rec *r, 
			apr_table_t *cookie) 
     
{
  
  return apr_pstrcat
    (r->pool,
     escape_sig(r->pool,apr_table_get(cookie, "ver")), "!",
     escape_sig(r->pool,apr_table_get(cookie, "status")), "!",
     escape_sig(r->pool,apr_table_get(cookie, "msg")), "!",
     escape_sig(r->pool,apr_table_get(cookie, "issue")), "!",
     escape_sig(r->pool,apr_table_get(cookie, "last")), "!",
     escape_sig(r->pool,apr_table_get(cookie, "life")), "!",
     escape_sig(r->pool,apr_table_get(cookie, "id")), "!",
     escape_sig(r->pool,apr_table_get(cookie, "principal")), "!",
     escape_sig(r->pool,apr_table_get(cookie, "auth")), "!",
     escape_sig(r->pool,apr_table_get(cookie, "sso")), "!",
     escape_sig(r->pool,apr_table_get(cookie, "params")), 
     NULL);
  
}

/* --- */

static char *
wls_response_check_sig_string(request_rec *r, 
			      apr_table_t *wls_response) {

  return apr_pstrcat
    (r->pool,
     escape_sig(r->pool,apr_table_get(wls_response, "ver")), "!",
     escape_sig(r->pool,apr_table_get(wls_response, "status")), "!",
     escape_sig(r->pool,apr_table_get(wls_response, "msg")), "!",
     escape_sig(r->pool,apr_table_get(wls_response, "issue")), "!",
     escape_sig(r->pool,apr_table_get(wls_response, "id")), "!",
     escape_sig(r->pool,apr_table_get(wls_response, "url")), "!",
     escape_sig(r->pool,apr_table_get(wls_response, "principal")), "!",
     escape_sig(r->pool,apr_table_get(wls_response, "auth")), "!",
     escape_sig(r->pool,apr_table_get(wls_response, "sso")), "!",
     escape_sig(r->pool,apr_table_get(wls_response, "life")), "!",
     escape_sig(r->pool,apr_table_get(wls_response, "params")), 
     NULL);

}

/* --- */

static apr_table_t *
unwrap_wls_token(request_rec *r, 
		 char *token_str) 
     
{
  
  const char *pair;
  char *word;
  apr_table_t *wls_token;
  pair = token_str;
  wls_token = (apr_table_t *)apr_table_make(r->pool, 11);
  
  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(wls_token,"ver",word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(wls_token,"status",word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);  
  apr_table_set(wls_token,"msg",word); 

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);  
  apr_table_set(wls_token,"issue",word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);  
  apr_table_set(wls_token,"id",word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);  
  apr_table_set(wls_token,"url",word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);  
  apr_table_set(wls_token,"principal",word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);  
  apr_table_set(wls_token,"auth",word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(wls_token,"sso",word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(wls_token,"life",word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(wls_token,"params",word); 

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(wls_token,"kid",word); 

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(wls_token,"sig",word); 
  
  return wls_token;

}

/* --- */
/* find the session cookie string from the request headers */

static char *
get_cookie_str(request_rec *r, 
	       char *cookie_name) 

{

  const char *data = apr_table_get(r->headers_in, "Cookie");

  const char *pair;

  APACHE_LOG0(APLOG_DEBUG, "get_cookie_str...");

  if (!data) return NULL;

  APACHE_LOG1(APLOG_DEBUG, "cookie data = %s", data);

  while (*data && (pair = ap_getword(r->pool, &data, ';'))) {
    const char *name;
    if (*data == ' ') ++data;
    name = ap_getword(r->pool, &pair, '=');
    
    APACHE_LOG1(APLOG_DEBUG, "current cookie name = %s", name);
    APACHE_LOG1(APLOG_DEBUG, "current cookie data = %s", pair);
    
    if (strcmp(name, cookie_name) == 0) {
      APACHE_LOG0(APLOG_DEBUG, "found cookie match!");
      ap_unescape_url((char*)pair);
      return (char *)pair;
    }
  }
  return NULL;

}
/* --- */
/* unwrap the session cookie into a table */

static apr_table_t *
make_cookie_table(request_rec *r, 
		  char *cookie_str) 

{

  const char *pair;
  char *word;
  apr_table_t *cookie;
  pair = cookie_str;
  cookie = (apr_table_t *)apr_table_make(r->pool, 11);
  
  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(cookie, "ver", word);
  
  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(cookie, "status", word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(cookie, "msg", word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(cookie, "issue", word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(cookie, "last", word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(cookie, "life", word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(cookie, "id", word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(cookie, "principal", word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(cookie, "auth", word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(cookie, "sso", word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(cookie, "params", word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(cookie, "key", word);

  word = (char *)ap_getword_nulls(r->pool, &pair, '!');
  ap_unescape_url(word);
  apr_table_set(cookie, "sig", word);

  return cookie;

}

/* --- */
/* wrap a session cookie table into a string for setting as a cookie */

static char *
make_cookie_str(request_rec *r,
		mod_ucam_webauth_cfg *c,
		apr_table_t *cookie)

{

  char *cookie_str;

  cookie_str = cookie_check_sig_string(r, cookie);

  cookie_str = apr_pstrcat
    (r->pool,
     cookie_str,
     "!1!",
     SHA1_sign(r, c, cookie_str),
     NULL);
  
  cookie_str = escape_url(r->pool, cookie_str);

  APACHE_LOG1(APLOG_DEBUG, "make_cookie_str: result = %s", cookie_str); 
  return cookie_str;

}

/* --- */

static char *
get_url(request_rec *r) 

{

  /* This is rumoured not to work, perhaps in Apache 2, perhaps
     depending on the presence (or otherwise) of ServerName and/or
     Port and/or Listen directive. Needs testing. */ 

  char *url, *result;
  apr_uri_t uri;

  url = ap_construct_url(r->pool, r->unparsed_uri, r);
  APACHE_LOG1(APLOG_DEBUG, "get_url: raw url = %s", url);

  /* ap_construct_url honours UseCannonicalName but we really don't
     want that so we re-parse this result and override the hostname
     component with what we know we are really called
  */

#ifdef APACHE1_3
  if (apr_uri_parse(r->pool, url, &uri) != HTTP_OK)
    APACHE_LOG0(APLOG_CRIT, "Failed to parse own URL");
#else
  if (apr_uri_parse(r->pool, url, &uri))
    APACHE_LOG0(APLOG_CRIT, "Failed to parse own URL");
#endif
  uri.hostname = r->server->server_hostname;
  result = apr_uri_unparse(r->pool, &uri, (unsigned)0);

  APACHE_LOG1(APLOG_DEBUG, "get_url: fixed url = %s", result);
  return result;

}

/* --- */

static void
cache_control(request_rec *r,
	      int option)

{

  if (option == CC_ON) {
    r->no_cache = 1;
    apr_table_add(r->headers_out, "Cache-Control", 
		     "no-cache");
    apr_table_add(r->headers_out, "Pragma", "no-cache");
  } else if (option == CC_PARANOID) {
    r->no_cache = 1;
    apr_table_add(r->headers_out, "Cache-Control", 
		     "no-store, no-cache, max-age=0, must-revalidate");
    apr_table_add(r->headers_out, "Pragma", "no-cache");
    apr_table_unset(r->headers_in, "If-Modified-Since");
  }

}
    
    
/* ---------------------------------------------------------------------- */

/* Error messages, custom error pages */

/* --- */

static char *
error_message(int err) {
  switch (err) {
  case 200 : return "OK";
  case 410 : return "Authentication cancelled at user's request";
  case 510 : return "No mutually acceptable types of authentication available";
  case 520 : return "Unsupported authentication protocol version";
  case 530 : return "Parameter error in authentication request";
  case 540 : return "Interaction with the user would be required";
  case 550 : return "Web server and authentication server clocks out of sync";
  case 560 : return "Web server not authorised to use "
                    "the authentication service";
  case 570 : return "Operation declined by the authentication service";
  }
  return "Unrecognised error code";

}

/* --- */

static char *
no_cookie(request_rec *r, 
	  mod_ucam_webauth_cfg *c) 

{

  char *cookie_name = 
    ap_escape_html(r->pool, full_cookie_name(r, c->cookie_name));
  char *sig = (char *)ap_psignature("<hr>", r);
  char *cookie_domain;
  if (c->cookie_domain != NULL) {
    cookie_domain = apr_pstrcat(r->pool,
				"computers in the domain <tt>",
				ap_escape_html(r->pool, c->cookie_domain),
				"</tt>", NULL);
  } else {
    cookie_domain = "this web server";
  }
  
  return apr_pstrcat
    (r->pool,
     "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
     "<html><head><title>Error - missing cookie</title></head>"
     "<body><h1>Error - missing cookie</h1>"
     "<p>The web resource you are trying to access is protected "
     "by a system that uses a browser cookie to track your "
     "authentication state. Your browser does not seem to be "
     "returning an appropriate cookie, probably because it has "
     "been configured to reject some or all cookies. To access "
     "this resource you must at least accept a cookie called "
     "'<tt><b>", cookie_name, "</b></tt>' from ", cookie_domain,
     ".<p>This can also happen if you follow a bookmark pointing "
     "a login page. This won't work - to create a shortcut to a "
     "protected resource you should bookmark the page you arrive "
     "at immediately after authenticating.<p>This cookie will be "
     "deleted when you quit your web browser. It contains your "
     "identity and other information used to manage authentication.", 
     sig, "</body></html>", NULL);

}


/* --- */

static char *
auth_cancelled(request_rec *r) 

{

  char *sig = (char *)ap_psignature("<hr>", r);
  char *admin = ap_escape_html(r->pool, r->server->server_admin);
  if (admin != NULL) {
    admin = apr_pstrcat(r->pool, "(<tt><b>", admin, "</b></tt>)", NULL);
  } else {
    admin = "";
  }

  return apr_pstrcat
    (r->pool,
     "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
     "<html><head><title>Error - authentication cancelled</title></head>"
     "<body><h1>Error - authentication cancelled</h1>"
     "<p>Authentication has been cancelled at your request. Unfortunately "
     "this means you will not be able to access the resource that you "
     "requested",
     "<p>If you cancelled authentication because you do not have a "
     "suitable username and password then you should contact the "
     "authentication system administrator to see if you can be "
     "registered. If you cancelled because of privacy concerns then you "
     "should contact the administrator of this server ", admin, " to see "
     "if there are other ways for you to access this resource.",
     sig, "</body></html>", NULL);

}

/* --- */

static char*
interact_required(request_rec *r) 

{

  char *sig = (char *)ap_psignature("<hr>", r);
  char *admin = ap_escape_html(r->pool, r->server->server_admin);
  if (admin != NULL) {
    admin = apr_pstrcat(r->pool, "(<tt><b>", admin, "</b></tt>)", NULL);
  } else {
    admin = "";
  }

  return apr_pstrcat
    (r->pool,
     "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
     "<html><head><title>Error - interaction required</title></head>"
     "<body><h1>Error - interaction required</h1>"
     "<p>Authentication cannot proceed because this server is configured "
     "to only serve the resource that you requested if the authentication "
     "system can authenticate you without interacting with you, and it "
     "cannot.",
     "<p>This error should not usually be seen by users, so if you have "
     "reached this message by a reasonable means you may wish to contact "
     "the administrator of this server ", admin, " to correct the problem.",
     sig, "</body></html>", NULL);

}

/* --- */

static char *
auth_required(request_rec *r) 

{

  char *sig = (char *)ap_psignature("<hr>", r);
  char *admin = ap_escape_html(r->pool, r->server->server_admin);
#ifdef APACHE1_3
  char *user = ap_escape_html(r->pool, r->connection->user);
#else
  char *user = ap_escape_html(r->pool, r->user);
#endif

  /* Apache core seems to default ServerAdmin to the unhelpful "[no
     address given]" */ 

  if (admin != NULL && strcmp(admin,"[no address given]") != 0) {
    admin = apr_pstrcat(r->pool, "(<tt><b>", admin, "</b></tt>)", NULL);
  } else {
    admin = "";
  }
  if (user != NULL) {
    user = apr_pstrcat(r->pool, "(<tt><b>", user, "</b></tt>)", NULL);
  } else {
    user = "";
  }

  return apr_pstrcat
    (r->pool,
     "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
     "<html><head><title>Error - authorization required</title></head>"
     "<body><h1>Error - authorization required</h1>"
     "<p>Access to the web page or other resource you are trying to "
     "obtain is restricted. The identity that you have established ", user,
     " is not currently allowed access. Please contact the "
     "administrator of the web server that provides the page ", 
      admin, " for further information.",
     sig,
     "\n\n"
     "<!-- This is padding to convince STUPID INTERNET EXPLORER that"
     "     I do know what I'm doing and that this error message"
     "     contains useful information. Without the padding, IE"
     "     will by default 'helpfully' display a useless error page"
     "     in place of my carefully crafted words. Bah!"
     "--></body></html>", NULL);

}

/* ---------------------------------------------------------------------- */

/* Config magic */

/* --- */
/* create per-directory config */

static void *
webauth_create_dir_config(apr_pool_t *p, 
			  char *path) 
     
{
  
  mod_ucam_webauth_cfg *cfg;

  cfg = 
    (mod_ucam_webauth_cfg *)apr_pcalloc(p, sizeof(mod_ucam_webauth_cfg));
  cfg->auth_service = NULL;
  cfg->logout_service = NULL;
  cfg->description = NULL;
  cfg->response_timeout = -1;
  cfg->clock_skew = -1;
  cfg->key_dir = NULL;
  cfg->max_session_life = -1;
  cfg->inactive_timeout = -1;
  cfg->timeout_msg = NULL;
  cfg->cache_control = -1;
  cfg->cookie_key = NULL;
  cfg->cookie_name = NULL;
  cfg->cookie_path = NULL;
  cfg->cookie_domain = NULL;
  cfg->force_interact = -1;
  cfg->refuse_interact = -1;
  cfg->fail = -1;
  cfg->ign_response_life = -1;
  cfg->cancel_msg = NULL;
  cfg->need_interact_msg = NULL;
  cfg->no_cookie_msg = NULL;
  cfg->logout_msg = NULL;
  cfg->always_decode = -1;
  cfg->headers = -1;
  cfg->header_key = NULL;  
  cfg->force_auth_type = NULL;
  return (void *)cfg;

}

/* --- */
/* merge per-directory config */

static void *
webauth_merge_dir_config(apr_pool_t *p, 
			 void *bconf,
			 void *nconf)
     
{

  mod_ucam_webauth_cfg *merged = 
    (mod_ucam_webauth_cfg *)apr_pcalloc(p, sizeof(mod_ucam_webauth_cfg)); 

  mod_ucam_webauth_cfg *base = (mod_ucam_webauth_cfg *)bconf;
  mod_ucam_webauth_cfg *new  = (mod_ucam_webauth_cfg *)nconf;

  merged->auth_service = new->auth_service != NULL ? 
    new->auth_service : base->auth_service;
  merged->logout_service = new->logout_service != NULL ? 
    new->logout_service : base->logout_service;
  merged->description = new->description != NULL ? 
    new->description : base->description;
  merged->response_timeout = new->response_timeout != -1 ? 
    new->response_timeout : base->response_timeout;
  merged->inactive_timeout = new->inactive_timeout != -1 ? 
    new->inactive_timeout : base->inactive_timeout;
  merged->clock_skew = new->clock_skew != -1 ? 
    new->clock_skew : base->clock_skew;
  merged->key_dir = new->key_dir != NULL ? 
    new->key_dir : base->key_dir;
  merged->max_session_life = new->max_session_life != -1 ? 
    new->max_session_life : base->max_session_life;
  merged->timeout_msg = new->timeout_msg != NULL ? 
    new->timeout_msg : base->timeout_msg;
  merged->cache_control = new->cache_control != -1 ? 
    new->cache_control : base->cache_control;
  merged->cookie_key = new->cookie_key != NULL ? 
    new->cookie_key : base->cookie_key;
  merged->cookie_name = new->cookie_name != NULL ? 
    new->cookie_name : base->cookie_name;
  merged->cookie_path = new->cookie_path != NULL ? 
    new->cookie_path : base->cookie_path;
  merged->cookie_domain = new->cookie_domain != NULL ? 
    new->cookie_domain : base->cookie_domain;
  merged->force_interact = new->force_interact != -1 ? 
    new->force_interact : base->force_interact;
  merged->refuse_interact = new->refuse_interact != -1 ? 
    new->refuse_interact : base->refuse_interact;
  merged->fail = new->fail != -1 ? 
    new->fail : base->fail;
  merged->ign_response_life = new->ign_response_life != -1 ? 
    new->ign_response_life : base->ign_response_life;
  merged->cancel_msg = new->cancel_msg != NULL ? 
    new->cancel_msg : base->cancel_msg;
  merged->need_interact_msg = new->need_interact_msg != NULL ? 
    new->need_interact_msg : base->need_interact_msg;
  merged->no_cookie_msg = new->no_cookie_msg != NULL ? 
    new->no_cookie_msg : base->no_cookie_msg;
  merged->logout_msg = new->logout_msg != NULL ? 
    new->logout_msg : base->logout_msg;
  merged->always_decode = new->always_decode != -1 ? 
    new->always_decode : base->always_decode;
  merged->headers = new->headers != -1 ? 
    new->headers : base->headers;
  merged->header_key = new->header_key != NULL ? 
    new->header_key : base->header_key;
  merged->force_auth_type = new->force_auth_type != NULL ? 
    new->force_auth_type : base->force_auth_type;

  return (void *)merged;

} 

/* --- */
/* apply the defaults to a merged config structure */

static mod_ucam_webauth_cfg *
apply_config_defaults(request_rec *r, 
                      mod_ucam_webauth_cfg *c)

{
    
  mod_ucam_webauth_cfg *n = 
    (mod_ucam_webauth_cfg *)apr_pcalloc(r->pool, sizeof(mod_ucam_webauth_cfg));

  n->auth_service = c->auth_service != NULL ? c->auth_service : 
      DEFAULT_auth_service; 
  n->logout_service = c->logout_service != NULL ? c->auth_service :
      DEFAULT_logout_service;
  n->description = c->description != NULL ? c->description : 
      DEFAULT_description;
  n->response_timeout = c->response_timeout != -1 ? c->response_timeout : 
      DEFAULT_response_timeout;
  n->clock_skew = c->clock_skew != -1 ? c->clock_skew :
      DEFAULT_clock_skew;
  n->key_dir = c->key_dir != NULL ? c->key_dir :
      ap_server_root_relative(r->pool,DEFAULT_key_dir);
  n->max_session_life = c->max_session_life != -1 ? c->max_session_life :
      DEFAULT_max_session_life;
  n->inactive_timeout = c->inactive_timeout != -1 ? c->inactive_timeout :
      DEFAULT_inactive_timeout;
  n->timeout_msg = c->timeout_msg != NULL ? c->timeout_msg :
      DEFAULT_timeout_msg;
  n->cache_control = c->cache_control != -1 ? c->cache_control :
      DEFAULT_cache_control;
  n->cookie_key = c->cookie_key != NULL ? c->cookie_key : 
      DEFAULT_cookie_key; 
  n->cookie_name = c->cookie_name != NULL ? c->cookie_name : 
      DEFAULT_cookie_name;
  n->cookie_path = c->cookie_path != NULL ? c->cookie_path :
      DEFAULT_cookie_path;
  n->cookie_domain = c->cookie_domain != NULL ? c->cookie_domain : 
      DEFAULT_cookie_domain;
  n->force_interact = c->force_interact != -1 ? c->force_interact :
      DEFAULT_force_interact;  
  n->refuse_interact = c->refuse_interact != -1 ? c->refuse_interact :
      DEFAULT_refuse_interact;  
  n->fail = c->fail != -1 ? c->fail :
      DEFAULT_fail; 
  n->ign_response_life = c->ign_response_life != -1 ? c->ign_response_life :
      DEFAULT_ign_response_life; 
  n->cancel_msg = c->cancel_msg != NULL ? c->cancel_msg : 
      DEFAULT_cancel_msg;
  n->need_interact_msg = c->need_interact_msg != NULL ? c->need_interact_msg : 
      DEFAULT_need_interact_msg;
  n->no_cookie_msg = c->no_cookie_msg != NULL ? c->no_cookie_msg : 
      DEFAULT_no_cookie_msg;
  n->logout_msg = c->logout_msg != NULL ? c->logout_msg : 
      DEFAULT_logout_msg;
  n->always_decode = c->always_decode != -1 ? c->always_decode :
      DEFAULT_always_decode;
  n->headers = c->headers != -1 ? c->headers :
      DEFAULT_headers;
  n->header_key = c->header_key != NULL ? c->header_key : 
      DEFAULT_header_key; 
  n->force_auth_type = c->force_auth_type != NULL ? c->force_auth_type : 
      DEFAULT_force_auth_type; 

  /* the string 'none' resets the various '...Msg' settings to default */

  if (n->timeout_msg && !strcasecmp(n->timeout_msg,"none"))
    n->timeout_msg = DEFAULT_timeout_msg;
  if (n->cancel_msg && !strcasecmp(n->cancel_msg,"none"))
    n->cancel_msg = DEFAULT_cancel_msg;
  if (n->need_interact_msg && !strcasecmp(n->need_interact_msg,"none"))
    n->need_interact_msg = DEFAULT_need_interact_msg;
  if (n->no_cookie_msg && !strcasecmp(n->no_cookie_msg,"none")) 
    n->no_cookie_msg = DEFAULT_no_cookie_msg;
  if (n->logout_msg && !strcasecmp(n->logout_msg,"none"))
    n->logout_msg = DEFAULT_logout_msg;

  return n;

}

/* --- */
/* dump a config structure */

static void 
dump_config(request_rec *r,
           mod_ucam_webauth_cfg *c)

{

  char *msg;

  if (r->server->loglevel >= APLOG_DEBUG) {

    APACHE_LOG0(APLOG_DEBUG, "Config dump:");
    
    APACHE_LOG1(APLOG_DEBUG, "  AAAuthService        = %s",
		(c->auth_service == NULL ? "NULL" : c->auth_service));
    
    APACHE_LOG1(APLOG_DEBUG, "  AALogoutService      = %s",
		(c->logout_service == NULL ? "NULL" : c->logout_service));
    
    APACHE_LOG1(APLOG_DEBUG, "  AADescription        = %s",
		(c->description == NULL ? "NULL" : c->description));
    
    APACHE_LOG1(APLOG_DEBUG, "  AAResponseTimeout    = %d",
		c->response_timeout);
    
    APACHE_LOG1(APLOG_DEBUG, "  AAClockSkew          = %d",
		c->clock_skew);
    
    APACHE_LOG1(APLOG_DEBUG, "  AAKeyDir             = %s",
		(c->key_dir == NULL ? "NULL" : c->key_dir));
    
    APACHE_LOG1(APLOG_DEBUG, "  AAMaxSessionLife     = %d",
		c->max_session_life);
    
    APACHE_LOG1(APLOG_DEBUG, "  AAInactiveTimeout    = %d",
		c->inactive_timeout);
    
    APACHE_LOG1(APLOG_DEBUG, "  AATimeoutMsg         = %s",
		(c->timeout_msg == NULL ? "NULL" : c->timeout_msg));
    
    switch(c->cache_control) {
    case CC_OFF:
      msg = "off";
      break;
    case CC_ON:
      msg = "on";
      break;
    case CC_PARANOID:
      msg = "paranoid";
      break;
    case -1:
      msg = "UNSET";
      break;
    default:
      msg = "unknown";
    }
    APACHE_LOG1(APLOG_DEBUG, "  AACacheControl       = %s", 
		msg);
    
    if (c->cookie_key == NULL) {
      APACHE_LOG0(APLOG_DEBUG, "  AACookieKey          = NULL");
    } else {
      APACHE_LOG2(APLOG_DEBUG, 
	    "  AACookieKey          = %-.4s... (%lu characters total)", 
		  c->cookie_key, (unsigned long)strlen(c->cookie_key));
    }
    
    APACHE_LOG1(APLOG_DEBUG, "  AACookieName         = %s",
		(c->cookie_name == NULL ? "NULL" : c->cookie_name));
    
    APACHE_LOG1(APLOG_DEBUG, "  AACookiePath         = %s",
		(c->cookie_path == NULL ? "NULL" : c->cookie_path));
    
    APACHE_LOG1(APLOG_DEBUG, "  AACookieDomain       = %s",
		(c->cookie_domain == NULL ? "NULL" : c->cookie_domain));
    
    APACHE_LOG1(APLOG_DEBUG, "  AAForceInteract      = %d",
		c->force_interact);
    
    APACHE_LOG1(APLOG_DEBUG, "  AARefuseInteract     = %d",
		c->refuse_interact);
    
    APACHE_LOG1(APLOG_DEBUG, "  AAFail               = %d",
		c->fail);
    
    APACHE_LOG1(APLOG_DEBUG, "  AAIgnoreResponseLife = %d",
		c->ign_response_life);
    
    APACHE_LOG1(APLOG_DEBUG, "  AACancelMsg          = %s",
		(c->cancel_msg == NULL ? "NULL" : c->cancel_msg));
    
    APACHE_LOG1(APLOG_DEBUG, "  AANeedInteractMsg    = %s",
		(c->need_interact_msg == NULL ? "NULL" : c->need_interact_msg));
    
    APACHE_LOG1(APLOG_DEBUG, "  AANoCookieMsg        = %s",
		(c->no_cookie_msg == NULL ? "NULL" : c->no_cookie_msg));
    
    APACHE_LOG1(APLOG_DEBUG, "  AALogoutMsg          = %s",
		(c->logout_msg == NULL ? "NULL" : c->logout_msg));
    
    APACHE_LOG1(APLOG_DEBUG, "  AAAlwaysDecode       = %d",
		c->always_decode);

    msg = "";
    if (c->headers & HDR_ISSUE)
      msg = apr_pstrcat(r->pool, msg, "Issue ", NULL);      
    if (c->headers & HDR_LAST)
      msg = apr_pstrcat(r->pool, msg, "Last ", NULL); 
    if (c->headers & HDR_LIFE)
      msg = apr_pstrcat(r->pool, msg, "Life ", NULL); 
    if (c->headers & HDR_TIMEOUT)
      msg = apr_pstrcat(r->pool, msg, "Timeout ", NULL);
    if (c->headers & HDR_ID)
      msg = apr_pstrcat(r->pool, msg, "ID ", NULL); 
    if (c->headers & HDR_PRINCIPAL)
      msg = apr_pstrcat(r->pool, msg, "Principal ", NULL); 
    if (c->headers & HDR_AUTH)
      msg = apr_pstrcat(r->pool, msg, "Auth ", NULL); 
    if (c->headers & HDR_SSO)
      msg = apr_pstrcat(r->pool, msg, "SSO", NULL);
    APACHE_LOG1(APLOG_DEBUG, "  AAHeaders            = %s",
		msg);

    if (c->header_key == NULL) {
      APACHE_LOG0(APLOG_DEBUG, "  AAHeaderKey          = NULL");
    } else {
      APACHE_LOG2(APLOG_DEBUG, 
	    "  AAHeaderKey          = %-.4s... (%lu characters total)", 
		  c->header_key, (unsigned long)strlen(c->header_key));
    }

    APACHE_LOG1(APLOG_DEBUG, "  AAForceAuthType      = %s",
		(c->force_auth_type == NULL ? "NULL" : c->force_auth_type));

  }

}

/* --- */

/* Note that most string and flag parameters are processed by the generic
   ap_set_string_slot and ap_set flag_slot routines */

static const char *
set_response_timeout(cmd_parms *cmd, 
		     void *mconfig, 
		     const char *arg) 
     
{

  mod_ucam_webauth_cfg *cfg = (mod_ucam_webauth_cfg *)mconfig;
 
  cfg->response_timeout = atoi(arg);
  if (cfg->response_timeout < 0) 
    return "AAResponseTimeout: must be a positive number";

  return NULL;

}

/* --- */

static const char *
set_clock_skew(cmd_parms *cmd, 
		void *mconfig, 
		const char *arg) 

{

  mod_ucam_webauth_cfg *cfg = (mod_ucam_webauth_cfg *)mconfig;

  cfg->clock_skew = atoi(arg);
  if (cfg->clock_skew < 0) 
    return "AAClockSkew: must be a positive number";

  return NULL;

}

/* --- */

static const char *
set_max_session_life(cmd_parms *cmd, 
		     void *mconfig, 
		     const char *arg) 

{

  mod_ucam_webauth_cfg *cfg = (mod_ucam_webauth_cfg *)mconfig;

  cfg->max_session_life = atoi(arg);
  if (cfg->max_session_life < 300) 
    return "AAMaxSessionLife: must be at least 300";
  return NULL;

}

/* --- */

static const char *
set_inactive_timeout(cmd_parms *cmd, 
		     void *mconfig, 
		     const char *arg) 

{

  mod_ucam_webauth_cfg *cfg = (mod_ucam_webauth_cfg *)mconfig;

  cfg->inactive_timeout = atoi(arg);
  if (cfg->inactive_timeout < 300) 
    return "AAInactiveTimeout: must be at least 300";
  return NULL;

}

/* --- */

static const char *
set_cache_control(cmd_parms *cmd, 
		  void *mconfig, 
		  const char *arg) 
     
{
  
  char *str;

  mod_ucam_webauth_cfg *cfg = (mod_ucam_webauth_cfg *)mconfig;
  
  if ((str = ap_getword_conf(cmd->pool, &arg))) {
    if (!strcasecmp(str, "off")) {
      cfg->cache_control = CC_OFF;
    }
    else if (!strcasecmp(str, "on")) {
      cfg->cache_control = CC_ON;
    }
    else if (!strcasecmp(str, "paranoid")) {
      cfg->cache_control = CC_PARANOID;
    }
    else {
      return "AACacheControl: unrecognised keyword - "
	"need one of off/on/paranoid";
    }
  }
  else {
    return "AACacheControl: missing keyword - "
      "need one of off/on/paranoid";
  }
  
  return NULL;

}

/* --- */

static const char *
set_log_level(cmd_parms *cmd, 
	      void *mconfig, 
	      const char *arg) 
     
{
  
#ifdef APACHE1_3
  ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_NOERRNO, cmd->server,
	       "The AALogLevel directive is deprecated and currently ignored");
#else
  ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server,
	       "The AALogLevel directive is deprecated and currently ignored");
#endif  
  
  return NULL;
  
}

/* --- */

static const char *
set_headers(cmd_parms *cmd, 
	    void *mconfig, 
	    const char *arg) 
     
{
  
  mod_ucam_webauth_cfg *cfg = (mod_ucam_webauth_cfg *)mconfig;
  
  cfg->headers = HDR_NONE;

  while (arg[0]) {

    char *word = ap_getword_conf(cmd->pool, &arg);

    if (!strcasecmp(word, "Issue")) {
      cfg->headers |= HDR_ISSUE;
    }
    else if (!strcasecmp(word, "Last")) {
      cfg->headers |= HDR_LAST;
    }
    else if (!strcasecmp(word, "Life")) {
      cfg->headers |= HDR_LIFE;
    }
    else if (!strcasecmp(word, "Timeout")) {
      cfg->headers |= HDR_TIMEOUT;
    }
    else if (!strcasecmp(word, "ID")) {
      cfg->headers |= HDR_ID;
    }
    else if (!strcasecmp(word, "Principal")) {
      cfg->headers |= HDR_PRINCIPAL;
    }
    else if (!strcasecmp(word, "Auth")) {
      cfg->headers |= HDR_AUTH;
    }
    else if (!strcasecmp(word, "SSO")) {
      cfg->headers |= HDR_SSO;
    }
    else if (!strcasecmp(word, "All")) {
      cfg->headers = HDR_ALL;
    }
    else if (!strcasecmp(word, "none")) {
      cfg->headers = HDR_NONE;
    }
    else {
      return "AAHeaders: unrecognised keyword - "
	"expecting one or more of 'Issue', 'Last', 'Life', 'Timeout', "
	"'ID', 'Principal', 'Auth', 'SSO', 'All', or 'None'";
    }
  }
  
  return NULL;
  
}

/* ---------------------------------------------------------------------- */

/* Handler logic */

static char *
add_hash(request_rec *r, 
	 const char *data,
	 char *key)

{

  unsigned char *hash = 
    (unsigned char *)apr_pcalloc(r->pool, EVP_MAX_MD_SIZE + 1);
  char *string, *encoded;
  unsigned int raw_len, enc_len;

  /* Do nothing if the key is 'none' */

  APACHE_LOG1(APLOG_DEBUG, "add_hash: data = %s", data); 

  if (!strcasecmp(key,"none"))
      return (char *)data;

  /* otherwise create the HMAC and encode it */

  string = apr_pstrcat(r->pool, data, key, NULL);

  HMAC(EVP_sha1(), key, strlen(key), 
       (const unsigned char *)string, strlen(string), hash, &raw_len);

  encoded = (char*)apr_palloc(r->pool, 1+apr_base64_encode_len(raw_len));
  enc_len = apr_base64_encode(encoded, (const char*)hash, raw_len);
  encoded[enc_len] = '\0';

  APACHE_LOG1(APLOG_DEBUG, "hash = %s", encoded);

  return apr_pstrcat(r->pool, encoded, " ", data, NULL);

}

/* --- */

static int
decode_cookie(request_rec *r, 
              mod_ucam_webauth_cfg *c)

{

  char *cookie_str, *new_cookie_str, *hkey;
  int life, cookie_verify;
  apr_table_t *cookie;
  apr_time_t issue, last, now;

  /* Check for config errors */
  
  if (c->cookie_key == NULL) {
    APACHE_LOG1(APLOG_CRIT,
		"Access to %s failed: AACookieKey not defined", r->uri);
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  
  if (r->parsed_uri.path != NULL &&
      apr_fnmatch(apr_pstrcat(r->pool, c->cookie_path, "*", NULL),
		  r->parsed_uri.path, 0) == APR_FNM_NOMATCH) {
    APACHE_LOG2(APLOG_CRIT, "AACookiePath %s is not a prefix of %s", 
		c->cookie_path, r->parsed_uri.path);
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  cookie_str = get_cookie_str(r, full_cookie_name(r, c->cookie_name));

  if (cookie_str == NULL || strcmp(cookie_str, TESTSTRING) == 0) {
    APACHE_LOG0(APLOG_INFO, "No existing authentication cookie");
    return DECLINED;
  }
  
  APACHE_LOG0(APLOG_INFO, "Found session cookie");
  APACHE_LOG1(APLOG_DEBUG, "cookie str = %s", cookie_str);
  
  cookie = make_cookie_table(r,  cookie_str);
    
  /* check cookie signature */
  
  cookie_verify = 
    SHA1_sig_verify(r, c, 
		    cookie_check_sig_string(r, cookie), 
		    (char *)apr_table_get(cookie, "sig"));
  
  if (cookie_verify == 0) {
    APACHE_LOG0(APLOG_ERR, "Session cookie invalid or key has changed"); 
    return DECLINED;
  }

  APACHE_LOG0(APLOG_INFO, "Session cookie signature valid"); 
      
  /* check cookie status */

  /* Note that if the stored status isn't 200 (OK) then we need to
     report the failure here and we reset the cookie to teststring so
     that if we come back through here again we will fall through and
     repeat the authentication */

  if (strcmp((char *)apr_table_get(cookie, "status"), "410") == 0) {
    APACHE_LOG0(APLOG_INFO, "Authentication status = 410, user cancelled"); 
    if (c->cancel_msg != NULL) {
      ap_custom_response(r, HTTP_FORBIDDEN, c->cancel_msg);
    } 
    else {
      ap_custom_response(r, HTTP_FORBIDDEN, auth_cancelled(r));
    }
    set_cookie(r, TESTSTRING, c);
    return HTTP_FORBIDDEN;
  }

  if (strcmp((char *)apr_table_get(cookie, "status"), "540") == 0) {
    APACHE_LOG0(APLOG_INFO, "Authentication status = 540, "
		"interaction required"); 
    if (c->need_interact_msg != NULL) {
      ap_custom_response(r, HTTP_BAD_REQUEST, c->need_interact_msg);
    } 
    else {
      ap_custom_response(r, HTTP_BAD_REQUEST, interact_required(r));
    }
    set_cookie(r, TESTSTRING, c);
    return HTTP_BAD_REQUEST;
  }

  if (strcmp((char *)apr_table_get(cookie, "status"), "200") != 0) {
    APACHE_LOG2(APLOG_ERR, "Authentication error, status = %s, %s",
		apr_table_get(cookie, "status"),
		apr_table_get(cookie, "msg"));
    set_cookie(r, TESTSTRING, c);
    return HTTP_BAD_REQUEST;
  }
  
  /* cookie timeout checks */
  
  APACHE_LOG3(APLOG_DEBUG, "issue = %s, last = %s, life = %s", 
	      (char *)apr_table_get(cookie, "issue"),
	      (char *)apr_table_get(cookie, "last"),
	      (char *)apr_table_get(cookie, "life"));
 
  issue = iso2_time_decode
    (r,(char *)apr_table_get(cookie, "issue"));
  last = iso2_time_decode
    (r,(char *)apr_table_get(cookie, "last"));
  life = atoi((char *)apr_table_get(cookie, "life"));
  
  if (issue == -1) {
    APACHE_LOG0(APLOG_ERR, "Session cookie issue date incorrect length"); 
    set_cookie(r, TESTSTRING, c);
    return HTTP_BAD_REQUEST;
  }
  if (last == -1) {
    APACHE_LOG0(APLOG_ERR, "Session cookie last use date incorrect length"); 
    set_cookie(r, TESTSTRING, c);
    return HTTP_BAD_REQUEST;
  }
  if (life <= 0) {
    APACHE_LOG0(APLOG_ERR, "Session cookie lifetime unreadable");
    set_cookie(r, TESTSTRING, c);
    return HTTP_BAD_REQUEST;
  }
  
  now = apr_time_now();
  
  APACHE_LOG4(APLOG_DEBUG, "now = %s, issue = %s, last = %s, life = %d", 
	      iso2_time_encode(r, now), iso2_time_encode(r, issue), 
	      iso2_time_encode(r, last), life);
  
  if (issue > now) {
    APACHE_LOG0(APLOG_ERR, "Session cookie has issue date in the future"); 
    set_cookie(r, TESTSTRING, c);
    return HTTP_BAD_REQUEST;
  } else if (last > now) {
    APACHE_LOG0(APLOG_ERR, "Session cookie has last used date in the future"); 
    set_cookie(r, TESTSTRING, c);
    return HTTP_BAD_REQUEST;
  } else if (now >= issue + apr_time_from_sec(life)) {
    APACHE_LOG0(APLOG_INFO, "Session cookie has expired"); 
    apr_table_set(r->notes,"AATimeout","expiry");
    return DECLINED;
  } else if (c->inactive_timeout && 
	     now >= last + apr_time_from_sec(c->inactive_timeout + 60)) {
    APACHE_LOG0(APLOG_INFO, "Session cookie has expired due to inactivity"); 
    apr_table_set(r->notes,"AATimeout","inactivity");
    return DECLINED;
  }

  /* otherwise it worked! Reset last if there is an inactivity timeout
     and more than 60 sec have passed. Note that this won't work for a
     304 Not modified response because Set-Cookie: headers are not
     allowed (and are not sent) in this case. Such is life */
  
  if (c->inactive_timeout && apr_time_sec(now - last) > 60) {
    apr_table_set(cookie,"last",iso2_time_encode(r, now));
    new_cookie_str = make_cookie_str(r, c, cookie);
    set_cookie(r, new_cookie_str, c);
  }
  
  /* save info for future use */
  
#ifdef APACHE1_3
  r->connection->user = (char *)apr_table_get(cookie, "principal");
  r->connection->ap_auth_type = c->force_auth_type;
#else
  r->user = (char *)apr_table_get(cookie, "principal");
  r->ap_auth_type = (char *) c->force_auth_type;
#endif
  
  apr_table_set(r->subprocess_env, 
		"AAISSUE", 
		apr_table_get(cookie, "issue"));
  apr_table_set(r->subprocess_env, 
		"AALAST", 
		apr_table_get(cookie, "last"));
  apr_table_set(r->subprocess_env, 
		"AALIFE", 
		apr_table_get(cookie, "life"));
  apr_table_set(r->subprocess_env, 
		"AATIMEOUT", 
		apr_psprintf(r->pool,"%d",c->inactive_timeout));
  apr_table_set(r->subprocess_env, 
		"AAID", 
		apr_table_get(cookie, "id"));
  apr_table_set(r->subprocess_env, 
		"AAPRINCIPAL", 
		apr_table_get(cookie, "principal"));
  apr_table_set(r->subprocess_env, 
		"AAAUTH", 
		apr_table_get(cookie, "auth"));
  apr_table_set(r->subprocess_env, 
		"AASSO", 
		apr_table_get(cookie, "sso"));

  /* Add additional headers */

  if (c->headers != HDR_NONE) {

    hkey = c->header_key;
    if (!hkey) {
      APACHE_LOG0(APLOG_ERR, "AAHeaders used but AAHeaderKey not set"); 
      return HTTP_INTERNAL_SERVER_ERROR;
    }
      
    if (c->headers & HDR_ISSUE)
      apr_table_set(r->headers_in, "X-AAIssue", 
		    add_hash(r,apr_table_get(cookie, "issue"),hkey));
    if (c->headers & HDR_LAST)
      apr_table_set(r->headers_in, "X-AAlast", 
		    add_hash(r,apr_table_get(cookie, "last"),hkey));
    if (c->headers & HDR_LIFE)
      apr_table_set(r->headers_in, "X-AALife", 
		    add_hash(r,apr_table_get(cookie, "life"),hkey));
    if (c->headers & HDR_TIMEOUT)
      apr_table_set(r->headers_in, "X-AATimeout", 
	      add_hash(r,apr_psprintf(r->pool,"%d",c->inactive_timeout),hkey));
    if (c->headers & HDR_ID)
      apr_table_set(r->headers_in, "X-AAID", 
		    add_hash(r,apr_table_get(cookie, "id"),hkey));
    if (c->headers & HDR_PRINCIPAL)
      apr_table_set(r->headers_in, "X-AAPrincipal", 
		    add_hash(r,apr_table_get(cookie, "principal"),hkey));
    if (c->headers & HDR_AUTH)
      apr_table_set(r->headers_in, "X-AAAuth", 
		    add_hash(r,apr_table_get(cookie, "auth"),hkey));
    if (c->headers & HDR_SSO)
      apr_table_set(r->headers_in, "X-AASSO", 
		    add_hash(r,apr_table_get(cookie, "sso"),hkey));

  }
  
  /* set a custom HTTP_UNAUTHORIZED page if there isn't one already
     because the default Apache one if misleading in a Ucam WebAuth
     context but will be displayed if the authz phase of mod_auth (or
     equivalent) returns HTTP_UNAUTHORIZED */
  
  if (wls_response_code_string(r, HTTP_UNAUTHORIZED) == NULL)
    ap_custom_response(r, HTTP_UNAUTHORIZED, auth_required(r));
  
  APACHE_LOG2(APLOG_INFO, "Successfully decoded cookie for %s accessing %s", 
	      (char *)apr_table_get(cookie, "principal"),r->uri);
  
  /* Even though we may have been successfull, we return DECLINED so
     as not to prevent other phases from running */

  return DECLINED;

}

/* --- */

/* Extract the WLS-Response CGI parameter (if there is one), unwrap it
   and check that the URL parameter is at least sane */

static int
decode_response(request_rec *r, 
		mod_ucam_webauth_cfg *c,
		apr_table_t **response)

{

  char *token_str;
  const char *this_url, *response_url;
  apr_table_t *response_ticket;

  /* See if we had a WLS-Response CGI parameter installed in our notes
     table by post_read_request. If we are a sub-request (r->main !=
     NULL) then user the corresponsing main request */

  token_str = get_cgi_param(r->main ? r->main : r, "WLS-Response");
  
  if (token_str == NULL)
    return DECLINED;

  APACHE_LOG1(APLOG_DEBUG, "WLS response data = %s", token_str);

  /* unwrap WLS token */
    
  ap_unescape_url(token_str);
  response_ticket = unwrap_wls_token(r, token_str);
    
  /* check that the URL in the token is plausible - note that if we
     are in a sub-request it's the URL from the coresponding main
     request that we need */  
  
  this_url = get_url(r->main ? r->main : r);
  this_url = ap_getword(r->pool, &this_url, '?');
  response_url = apr_table_get(response_ticket, "url");
  response_url = ap_getword(r->pool, &response_url, '?');

  if (strcmp(response_url, this_url) != 0) {
    APACHE_LOG2
      (APLOG_ERR, "URL in WLS response doesn't match this URL - %s != %s",
       response_url, this_url);
    return HTTP_BAD_REQUEST;
  }

  *response = response_ticket;
  return OK;

}

/* --- */

static int
validate_response(request_rec *r, 
		  mod_ucam_webauth_cfg *c,
		  apr_table_t *response_ticket)

{

  char *cookie_str, *new_cookie_str, *msg, *status, *url;
  int life, response_ticket_life, sig_verify_result;
  apr_table_t *cookie;
  apr_time_t issue, now;

  /* Check that cookie exists because it should have been created
     previously and if it's not there we'll probably end up in a
     redirect loop */
  
  APACHE_LOG1(APLOG_DEBUG, "Searching for cookie %s", c->cookie_name);
  
  cookie_str = get_cookie_str(r, full_cookie_name(r, c->cookie_name));
  if (cookie_str == NULL) {
    APACHE_LOG0(APLOG_WARNING, "Browser not accepting session cookie"); 
    if (c->no_cookie_msg != NULL) {
      ap_custom_response(r, HTTP_BAD_REQUEST, c->no_cookie_msg);
    } else {
      ap_custom_response(r, HTTP_BAD_REQUEST, no_cookie(r, c));
    }
    return HTTP_BAD_REQUEST;
  }

  msg = "";
  status = "200";
  
  /* do all the validations  - protocol version first */
    
  APACHE_LOG0(APLOG_DEBUG, "validating version"); 
  if (response_ticket == NULL)
    APACHE_LOG0(APLOG_DEBUG, "response_ticket is NULL"); 
  if (strcmp((char *)apr_table_get(response_ticket, "ver"), 
	     PROTOCOL_VERSION) != 0) {
    msg = apr_psprintf
      (r->pool,"Wrong protocol version (%s) in WLS response",
       (char *)apr_table_get(response_ticket, "ver"));
    status = "600";
    goto FINISHED;
  }
  APACHE_LOG0(APLOG_DEBUG, "validated version");
  
  /* status */
  
  if (strcmp(apr_table_get(response_ticket, "status"), 
	     "200") != 0) {
    msg = error_message(atoi(apr_table_get(response_ticket, "status")));
    if (apr_table_get(response_ticket, "msg") != NULL) {
      msg = apr_pstrcat(r->pool, msg, 
			apr_table_get(response_ticket, "msg"), NULL);
    }
    status = (char*)apr_table_get(response_ticket, "status");
    goto FINISHED;
  }
  
  /* issue time */
  
  now = apr_time_now();
  issue = 
    iso2_time_decode(r, (char *)apr_table_get(response_ticket, "issue"));
  
  if (issue < 0) {
    msg = apr_psprintf
      (r->pool,"Can't to parse issue time (%s) in WLS response",
       (char *)apr_table_get(response_ticket, "issue"));
    status = "600";
    goto FINISHED;
  }
  
  if (issue > now + apr_time_from_sec(c->clock_skew) + 1) {
    msg = apr_psprintf
      (r->pool,"WLS response issued in the future "
       "(local clock incorrect?); issue time %s",
       (char *)apr_table_get(response_ticket, "issue"));
    status = "600";
    goto FINISHED;
  }
  
  if (now - apr_time_from_sec(c->clock_skew) - 1 > 
      issue + apr_time_from_sec(c->response_timeout)) {
    msg = apr_psprintf
      (r->pool,"WLS response issued too long ago "
       "(local clock incorrect?); issue time %s",
       (char *)apr_table_get(response_ticket, "issue"));
    status = "600";
    goto FINISHED;
  }
  
  /* first-hand authentication if ForceInteract */
  
  if (c->force_interact == 1 && 
      apr_table_get(response_ticket, "auth") == "") {
    msg = "Non first-hand authentication under ForceInteract";
    status = "600";
    goto FINISHED;
  }
  
  /* signature valid */
  
  sig_verify_result = 
    RSA_sig_verify(r, 
		   wls_response_check_sig_string(r, response_ticket),
		   (char *)apr_table_get(response_ticket, "sig"), 
		   c->key_dir,
		   (char *)apr_table_get(response_ticket, "kid"));
  
  if (sig_verify_result == HTTP_BAD_REQUEST) {
    msg = "Missing or invalid signature in authentication service reply";
    status = "600";
    goto FINISHED;
  }
  else if (sig_verify_result != OK) {
    msg = "Web server configuration error";
    status = "600";
    goto FINISHED;
  } 
  
  /* seems OK */
  
 FINISHED:

  /* calculate session expiry */
  
  life = c->max_session_life;
  response_ticket_life = atoi(apr_table_get(response_ticket, "life"));

  if (c->ign_response_life == 1) {
    APACHE_LOG2(APLOG_DEBUG, "Ignoring WLS ticket_life = %d, using life = %d",
		response_ticket_life, life);
  } else {
    /* obey the normal rules */
    if (response_ticket_life > 0 && response_ticket_life < life)
      life = response_ticket_life;
  }
  
  APACHE_LOG1(APLOG_DEBUG, "life = %d", life);
  
  if (strcmp(status,"200") == 0 && life <= 0) {
    msg = "Requested session expiry time less that one second";
    status = "600";
  }
  
  /* log the outcome */
  
  if (strcmp(status,"200") == 0) {
    APACHE_LOG2
      (APLOG_INFO, "Successfully validated WLS response ID %s, principal %s", 
       apr_table_get(response_ticket, "id"),
       apr_table_get(response_ticket, "principal"));
  } else {
    APACHE_LOG3
      (APLOG_ERR, "Failed to validate WLS response ID %s: %s: %s", 
       apr_table_get(response_ticket, "id"), status, msg);
  }
  
  /* set new session ticket (cookie) */
  
  cookie = (apr_table_t *)apr_table_make(r->pool, 11);
  
  apr_table_set(cookie, "ver", 
		apr_table_get(response_ticket, "ver"));
  apr_table_set(cookie, "status", 
		status);
  apr_table_set(cookie, "msg", 
		msg);
  apr_table_set(cookie, "issue", 
		iso2_time_encode(r, apr_time_now())); 
  apr_table_set(cookie, "last",  
		iso2_time_encode(r, apr_time_now()));
  apr_table_set(cookie, "life", 
		apr_psprintf(r->pool,"%d",life));
  apr_table_set(cookie, "id", 
		apr_table_get(response_ticket, "id"));
  apr_table_set(cookie, "principal", 
		apr_table_get(response_ticket, "principal"));
  apr_table_set(cookie, "auth", 
		apr_table_get(response_ticket, "auth"));
  apr_table_set(cookie, "sso", 
		apr_table_get(response_ticket, "sso"));
  apr_table_set(cookie, "params", 
		apr_table_get(response_ticket, "params"));
  
  new_cookie_str = make_cookie_str(r, c, cookie);
  APACHE_LOG1(APLOG_DEBUG, "session ticket = %s", new_cookie_str);
  set_cookie(r, new_cookie_str, c);  
  
  /* redirect */
  
  url = (char *)apr_table_get(response_ticket, "url"); 
  APACHE_LOG1(APLOG_INFO, "Issuing redirect to original URL %s", url);
  
  apr_table_set(r->headers_out, 
		"Location", 
		url);
  
  return (r->method_number == M_GET) ? 
    HTTP_MOVED_TEMPORARILY : HTTP_SEE_OTHER;

}

/* --- */

static int
construct_request(request_rec *r, 
		  mod_ucam_webauth_cfg *c)

{

  char *request;
  
  /* We might be here as the result of a sub-request if it triggered
     authentication but the main request didn't. We can't send out
     current URL to the WLS becasue if we do we'll eventually be
     redirected back there and there is a fair chance that actually
     requesting it will fail. So we actually send the WLS the URL from
     the main request and trap that specially when the sub-request is
     eventually re-run */
  
  request = apr_pstrcat
    (r->pool,
     "ver=", PROTOCOL_VERSION,
     "&url=", escape_url(r->pool,get_url(r->main ? r->main : r)),
     "&date=", 
     iso2_time_encode(r, apr_time_now()),
     NULL);
  
  if (c->description != NULL)
    request = apr_pstrcat
      (r->pool, 
       request, 
       "&desc=", escape_url(r->pool,c->description), 
       NULL);
  
  if (apr_table_get(r->notes, "AATimeout") != NULL)
    request = apr_pstrcat
      (r->pool, 
       request, 
       "&msg=", escape_url(r->pool,c->timeout_msg), 
       NULL);
  
  if (c->fail == 1)
    request = apr_pstrcat(r->pool, request, "&fail=yes", NULL);
  
  if (c->force_interact == 1) 
    request = apr_pstrcat(r->pool, request, "&iact=yes", NULL);
  else if (c->refuse_interact == 1) 
    request = apr_pstrcat(r->pool, request, "&iact=no", NULL);
  
  request = apr_pstrcat
    (r->pool,
     c->auth_service, 
     "?",
     request,
     NULL);
  
  APACHE_LOG1(APLOG_DEBUG, "request = %s", request);
  
  apr_table_set(r->headers_out, "Location", request);
  set_cookie(r, TESTSTRING, c);
  
  APACHE_LOG1(APLOG_INFO, "Redirecting to login server at %s",
	      c->auth_service);
  
  return (r->method_number == M_GET) ? HTTP_MOVED_TEMPORARILY : HTTP_SEE_OTHER;

}

/* ---------------------------------------------------------------------- */

/* Initializer */

/* --- */

#ifdef APACHE1_3

static void
webauth_init(server_rec *s, apr_pool_t *p) 
     
{
  
  ap_add_version_component("mod_ucam_webauth/" VERSION);

}

#else  

static int 
webauth_init(apr_pool_t *p, 
	     apr_pool_t *l, 
	     apr_pool_t *t, 
	     server_rec *s)
     
{
  
  ap_add_version_component(p, "mod_ucam_webauth/" VERSION);
  return OK;

}

#endif

/* ---------------------------------------------------------------------- */

/* Post read request */
   
static int
webauth_post_read_request(request_rec *r)
     
{

  /* In some cases (mod_rewrite with a proxy target that includes a
     query string for example) r->args has been overriten by a new
     value by the time webauth_authn gets to run. So we save a copy of
     the _original_ args for future reference */ 

  APACHE_LOG2(APLOG_DEBUG, "post_read_request: for %s, args %s", 
	      r->uri, r->args);

  if (r->args != NULL) 
    apr_table_set(r->notes, "AA_orig_args", r->args); 

  return DECLINED;

}

/* ---------------------------------------------------------------------- */

/* Main auth handler */

/* --- */

static int  
webauth_authn(request_rec *r) 
     
{
  
  mod_ucam_webauth_cfg *c;
  apr_table_t *response = NULL;
  int rc;
  char *host, *colon;
  
  /* Do anything? */

  if (ap_auth_type(r) == NULL || 
      (strcasecmp(ap_auth_type(r), AUTH_TYPE1) != 0 &&
       strcasecmp(ap_auth_type(r), AUTH_TYPE2) != 0)) {
    APACHE_LOG2
      (APLOG_DEBUG,"mod_ucam_webauth authn handler declining for %s "
       "(AuthType = %s)",
       r->uri, ap_auth_type(r) == NULL ? "(null)" : ap_auth_type(r));
    return DECLINED;
  }
  
  APACHE_LOG2
    (APLOG_INFO, "** mod_ucam_webauth (%s) authn handler started for %s", 
     VERSION, r->uri);

  /* If the hostname the user used (as reported by the 'Host' header)
     doesn't match the configured hostname for this server then we are
     going to have all sorts of problems with cookies and redirects,
     so fix it (with a redirect) now. */

  host = apr_pstrdup(r->pool,apr_table_get(r->headers_in, "Host"));
  if (host != NULL) {
    colon = strchr(host,':');
    if (colon != NULL)
      *colon = '\0';
    if (r->server->server_hostname && 
	strcasecmp(r->server->server_hostname,host)) {
      colon = strchr(host,':');
      if (colon != NULL)
	*colon = '\0'; 
      APACHE_LOG2
	(APLOG_DEBUG,"Browser supplied hostname (%s) does not match "
	 "configured hostname (%s) - redirecting",
	 host, r->server->server_hostname);
      apr_table_set(r->headers_out, "Location", get_url(r));
      return (r->method_number == M_GET) ? 
	HTTP_MOVED_TEMPORARILY : HTTP_SEE_OTHER;
    }
  }
  
  c = (mod_ucam_webauth_cfg *) 
    ap_get_module_config(r->per_dir_config, &ucam_webauth_module);
  c = apply_config_defaults(r,c);

  dump_config(r,c);
  
  cache_control(r,c->cache_control);

  rc = decode_cookie(r,c);
  if (rc != DECLINED)
    return rc;

  /* main processing */

  /* look to see if we have a WLS Response in the URL and if so
     extract it. If that worked but we also found a cookie then just
     redirect to the URL from the response to clear the browser's
     location bar */

  rc = decode_response(r, c, &response);
  if (rc != OK && rc != DECLINED) 
    return rc;

  if (rc == OK) {
    APACHE_LOG0(APLOG_INFO, "Found a WLS response");
    if (apr_table_get(r->subprocess_env, "AAPrincipal")) {
      APACHE_LOG0(APLOG_INFO, "Alredy authenticated - redirecting");
      apr_table_set(r->headers_out, 
		    "Location", 
		    apr_table_get(response, "url"));
      return (r->method_number == M_GET) ? 
	HTTP_MOVED_TEMPORARILY : HTTP_SEE_OTHER;
    }
    APACHE_LOG0(APLOG_INFO, "Validating response");
    rc = validate_response(r, c, response);
    if (rc != DECLINED)
      return rc;
  }
  
  /* having got this far we can return if we got an identity from the
     cookie */

  if (apr_table_get(r->subprocess_env, "AAPrincipal")) {
    APACHE_LOG2(APLOG_INFO, "Successfully authenticated %s accessing %s", 
       (char *)apr_table_get(r->subprocess_env, "AAPrincipal"),r->uri);
    return OK;
  }

  /* and if none of that worked then send a request to the WLS. While
     we are at it then set a test value cookie so we can test that
     it's still available when we get back. */
  
  APACHE_LOG0(APLOG_INFO, "Generating WLS request");

  if (r->method_number == M_POST)
    APACHE_LOG0(APLOG_WARNING, "Redirect required on a POST request - "
       "POSTed data will be lost");
  
  return construct_request(r,c);

}

/* ---------------------------------------------------------------------- */

/* Fixup */

static int  
webauth_fixup(request_rec *r)
     
{
  
  /* Decode any session cookie that happens to be lying around if
     AAAlwaysDecode is in effect or we already did so in the auth
     handler */

  mod_ucam_webauth_cfg *c;

  c = (mod_ucam_webauth_cfg *) 
    ap_get_module_config(r->per_dir_config, &ucam_webauth_module); 
  c = apply_config_defaults(r,c);

  if (!c->always_decode  ||
      apr_table_get(r->subprocess_env, "AAPrincipal") != NULL) {
    APACHE_LOG3
      (APLOG_DEBUG,"mod_ucam_webauth fixup handler declining for %s "
       "(AAAlwaysDecode = %d, AAPrincipal = %s)", r->uri, c->always_decode,
       apr_table_get(r->subprocess_env, "AAPrincipal"));
    return DECLINED;
  }

  APACHE_LOG2
    (APLOG_INFO, "** mod_ucam_webauth (%s) fixup handler started for %s", 
     VERSION, r->uri);

  dump_config(r,c);
  
  /* Discard the result of decoding - either it worked or it didn't */
  (void)decode_cookie(r,c);
  
  return DECLINED; 

}

/* ---------------------------------------------------------------------- */

/* Logout page content handler */

/* --- */

static int  
webauth_handler_logout(request_rec *r) 
     
{

  mod_ucam_webauth_cfg *c;
  char *response;

  char *sig = (char *)ap_psignature("<hr>", r);

  if (strcasecmp(r->handler, "aalogout")) {
    APACHE_LOG0(APLOG_DEBUG, "logout_handler: declining");
    return DECLINED;
  }
  
  APACHE_LOG2(APLOG_INFO,
	      "** mod_ucam_webauth (%s) logout handler started for %s",
	      VERSION, r->uri);

  c = (mod_ucam_webauth_cfg *) 
    ap_get_module_config(r->per_dir_config, &ucam_webauth_module);
  c = apply_config_defaults(r,c);
  dump_config(r,c);  
  
  cache_control(r,c->cache_control);

  set_cookie(r, TESTSTRING, c);
  response = c->logout_msg;

  if (response && ap_is_url(response)) {
    APACHE_LOG1(APLOG_DEBUG, "logout_handler: redirecting to %s",
		response);
    apr_table_set(r->headers_out, "Location", response);
    return HTTP_MOVED_TEMPORARILY;
  } else if (response && *response == '/') {
    APACHE_LOG1(APLOG_DEBUG, "logout_handler: internal redirect to %s",
		response);
    ap_internal_redirect(response,r);
    return OK;
  }

  if (response && *response == '"') ++response;

  r->content_type = "text/html";
#ifdef APACHE1_3
  ap_send_http_header(r);
#endif

  APACHE_LOG0(APLOG_DEBUG, "logout_handler: sending response");

  if (response == NULL) {
    response = apr_pstrcat
      (r->pool,
       "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
       "<html><head><title>Logout</title></head>"
       "<body><h1>Logout</h1>"
       "<p>You have logged out of this site."
       "<p>If you have finished browsing, then you should completely "
       "exit your web browser. This is the best way to prevent others "
       "from accessing your personal information and visiting web sites "
       "using your identity. If for any reason you can't exit your browser "
       "you should first log-out of all other personalized sites that you "
       "have accessed and then <a href=\"", c->logout_service, 
       "\">logout from the central authentication service</a>.",
       sig, "</body></hmtl>", NULL);
  }
  ap_rputs(response,r);
  return OK;

}

/* ---------------------------------------------------------------------- */

/* configuration directives table */

static const command_rec webauth_commands[] = {

  AP_INIT_TAKE1("AAAuthService", 
		ap_set_string_slot, 
		(void *)APR_OFFSETOF
		(mod_ucam_webauth_cfg,auth_service), 
		RSRC_CONF | OR_AUTHCFG,
		"the URL of the authentication service at the WLS"),
  
  AP_INIT_TAKE1("AALogoutService", 
		ap_set_string_slot, 
		(void *)APR_OFFSETOF
		(mod_ucam_webauth_cfg,logout_service), 
		RSRC_CONF | OR_AUTHCFG,
		"the url of the logout service at the WLS"),
  
  AP_INIT_TAKE1("AADescription", 
		ap_set_string_slot,
		(void *)APR_OFFSETOF
		(mod_ucam_webauth_cfg,description), 
		RSRC_CONF | OR_AUTHCFG,
		"a description of the protected resource"),
  
  AP_INIT_TAKE1("AAResponseTimeout", 
		set_response_timeout, 
		NULL, 
		RSRC_CONF | OR_AUTHCFG,
		"the expected maximum delay in receiving response message "
		"from the authentication server (seconds)"),
  
  AP_INIT_TAKE1("AAClockSkew", 
		set_clock_skew, 
		NULL, 
		RSRC_CONF | OR_AUTHCFG,
		"the maximum expected difference between this "
		"server's clock and the one on the WLS (seconds)"),
  
  AP_INIT_TAKE1("AAKeyDir", 
		ap_set_file_slot,
		(void *)APR_OFFSETOF(mod_ucam_webauth_cfg,key_dir), 
		RSRC_CONF | OR_AUTHCFG,
		"the directory containing WLS keys (relative to "
		"server root if not absolute)"),
  
  AP_INIT_TAKE1("AAMaxSessionLife", 
		set_max_session_life, 
		NULL, 
		RSRC_CONF | OR_AUTHCFG,
		"the hard session timeout (seconds)"),
  
  AP_INIT_FLAG("AAIgnoreResponseLife",
		ap_set_flag_slot, 
		(void *)APR_OFFSETOF(mod_ucam_webauth_cfg,ign_response_life),
		RSRC_CONF | OR_AUTHCFG,
		"either 'on' or 'off'; "
		"'on' prevents the session timeout set by AAMaxSessionLife "
		"from being overriden by a shorter 'life' parameter from the "
                "authentication service response mesage"),

  AP_INIT_TAKE1("AAInactiveTimeout", 
		set_inactive_timeout, 
		NULL, 
		RSRC_CONF | OR_AUTHCFG,
		"the session inactivity timeout (seconds)"),
  
  AP_INIT_TAKE1("AATimeoutMsg", 
		ap_set_string_slot, 
		(void *)APR_OFFSETOF
		(mod_ucam_webauth_cfg,timeout_msg),
		RSRC_CONF | OR_AUTHCFG,
		"a message for display by the WLS when "
		"authentication is caused by session expiry"),
  
  AP_INIT_TAKE1("AACacheControl", 
		set_cache_control, 
		NULL, 
		RSRC_CONF | OR_AUTHCFG,
		"'off' to suppress cache control headers; "
                "'on' to disable most shared caching; "
		"'paranoid' to do everything possible to discourage "
                "re-use of cached content"),
  
  AP_INIT_TAKE1("AACookieKey", 
		ap_set_string_slot, 
		(void *)APR_OFFSETOF
		(mod_ucam_webauth_cfg,cookie_key), 
		RSRC_CONF | OR_AUTHCFG,
		"the secret key for session cookie (required)"),
  
  AP_INIT_TAKE1("AACookieName", 
		ap_set_string_slot, 
		(void *)APR_OFFSETOF
		(mod_ucam_webauth_cfg,cookie_name), 
		RSRC_CONF | OR_AUTHCFG,
		"the name of the session cookie"),
  
  AP_INIT_TAKE1("AACookiePath", 
		ap_set_string_slot, 
		(void *)APR_OFFSETOF
		(mod_ucam_webauth_cfg,cookie_path), 
		RSRC_CONF | OR_AUTHCFG,
		"a path prefix for the session cookie"),
  
  AP_INIT_TAKE1("AACookieDomain", 
		ap_set_string_slot, 
		(void *)APR_OFFSETOF
		(mod_ucam_webauth_cfg,cookie_domain),
		RSRC_CONF | OR_AUTHCFG,
		"the domain setting for session cookie"),
  
  AP_INIT_FLAG("AAForceInteract", 
	       ap_set_flag_slot, 
	       (void *)APR_OFFSETOF
	       (mod_ucam_webauth_cfg,force_interact),
	       RSRC_CONF | OR_AUTHCFG,
	       "either 'on' or 'off'; "
	       "'on' suppresses 'single sign-on' at the WLS"),
  
  AP_INIT_FLAG("AARefuseInteract", 
	       ap_set_flag_slot, 
	       (void *)APR_OFFSETOF
	       (mod_ucam_webauth_cfg,refuse_interact),
	       RSRC_CONF | OR_AUTHCFG,
	       "either 'on' or 'off'; "
	       "'on' asks WLS not to interact with user"),
  
  AP_INIT_FLAG("AAFail", 
	       ap_set_flag_slot, 
	       (void *)APR_OFFSETOF(mod_ucam_webauth_cfg,fail),
	       RSRC_CONF | OR_AUTHCFG,
	       "either 'on' or 'off'; "
	       "'on' causes the WLS to report errors directly"),
  
  AP_INIT_TAKE1("AACancelMsg", 
		ap_set_string_slot, 
		(void *)APR_OFFSETOF
		(mod_ucam_webauth_cfg,cancel_msg),
		RSRC_CONF | OR_AUTHCFG,
		"a custom error definition for 'authentication cancelled'"),
  
  AP_INIT_TAKE1("AANeedInteractMsg", 
		ap_set_string_slot, 
		(void *)APR_OFFSETOF
		(mod_ucam_webauth_cfg,need_interact_msg),
		RSRC_CONF | OR_AUTHCFG,
		"a custom error definition for 'interaction required'"),
  
  AP_INIT_TAKE1("AANoCookieMsg", 
		ap_set_string_slot, 
		(void *)APR_OFFSETOF
		(mod_ucam_webauth_cfg,no_cookie_msg), 
		RSRC_CONF | OR_AUTHCFG,
		"a custom error definition for 'no cookie'"),
  
  AP_INIT_TAKE1("AALogoutMsg", 
		ap_set_string_slot, 
		(void *)APR_OFFSETOF
		(mod_ucam_webauth_cfg,logout_msg), 
		RSRC_CONF | OR_AUTHCFG,
		"a message or page to display on visiting the logout URL"),
  
  AP_INIT_TAKE1("AALogLevel", 
		set_log_level, 
		NULL, 
		RSRC_CONF | OR_AUTHCFG,
		"THIS DIRECTIVE IS DEPRECATED AND IGNORED"),
  
  AP_INIT_FLAG("AAAlwaysDecode", 
	       ap_set_flag_slot, 
	       (void *)APR_OFFSETOF
	       (mod_ucam_webauth_cfg,always_decode),
	       RSRC_CONF | OR_AUTHCFG,
	       "either 'on' or 'off'; "
	       "session cookies are always decoded"),

  AP_INIT_RAW_ARGS("AAHeaders", 
		   set_headers, 
		   NULL,
		   RSRC_CONF | OR_AUTHCFG,
		   "a list of additional headers to include in the request"),

  AP_INIT_TAKE1("AAHeaderKey", 
		ap_set_string_slot, 
		(void *)APR_OFFSETOF
		(mod_ucam_webauth_cfg,header_key), 
		RSRC_CONF | OR_AUTHCFG,
		"the secret key for additional headers (required)"),

  AP_INIT_TAKE1("AAForceAuthType", 
		ap_set_string_slot, 
		(void *)APR_OFFSETOF
		(mod_ucam_webauth_cfg,force_auth_type), 
		RSRC_CONF | OR_AUTHCFG,
		"override the returned authentication type"),
  
  {NULL}

};

/* ---------------------------------------------------------------------- */

/* make Apache aware of the handlers */

#ifdef APACHE1_3

static const handler_rec webauth_handlers[] = {
  { "aalogout", webauth_handler_logout },
  { NULL }
};

module MODULE_VAR_EXPORT ucam_webauth_module = {
  STANDARD_MODULE_STUFF,
  webauth_init,                 /* initializer */
  webauth_create_dir_config,    /* dir config creator */
  webauth_merge_dir_config,     /* dir merger --- default is to override */
  NULL,                         /* server config */
  NULL,                         /* merge server config */
  webauth_commands,             /* command table */
  webauth_handlers,             /* handlers */
  NULL,                         /* filename translation */
  webauth_authn,                /* check_user_id */
  NULL,                         /* check auth */
  NULL,                         /* check access */
  NULL,                         /* type_checker */
  webauth_fixup,                /* fixups */
  NULL,                         /* logger */
  NULL,                         /* header parser */
  NULL,                         /* child_init */
  NULL,                         /* child_exit */
  webauth_post_read_request     /* post read-request */
};

#else

static void webauth_register_hooks(apr_pool_t *p) {
  ap_hook_post_config
    (webauth_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_post_read_request
    (webauth_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_check_user_id
    (webauth_authn, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_handler
    (webauth_handler_logout, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_fixups
    (webauth_fixup, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA ucam_webauth_module = {
  STANDARD20_MODULE_STUFF,
  webauth_create_dir_config,    /* create per-directory config structures */
  webauth_merge_dir_config,     /* merge per-directory config structures  */
  NULL,                         /* create per-server config structures    */
  NULL,                         /* merge per-server config structures     */
  webauth_commands,             /* command handlers */
  webauth_register_hooks        /* register hooks */
};

#endif

/* ---------------------------------------------------------------------- */



