/* 

   University of Cambridge Web Authentication System
   Application Agent for Apache 1.3 and 2
   See http://raven.cam.ac.uk/ for more details

   $Id: mod_ucam_webauth.c,v 1.10 2004-06-16 15:47:53 jw35 Exp $

   Copyright (c) University of Cambridge 2004 
   See the file NOTICE for conditions of use and distribution.

   Author: Robin Brady-Roche <rbr268@cam.ac.uk>, based on a mod_perl
   application agent by Jon Warbrick <jw35@cam.ac.uk>

*/

#define VERSION "0.45"

/*
MODULE-DEFINITION-START
Name: ucam_webauth_module
ConfigStart
  LIBS="$LIBS -lcrypto"
  echo " + using -lcrypto to include OpenSSL library"
ConfigEnd
MODULE-DEFINITION-END
*/

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

#include <string.h>
#include <time.h>

/* ---------------------------------------------------------------------- */

#if defined APACHE_RELEASE && APACHE_RELEASE < 20000000

/* APACHE 1.3 */

/* include */

#include "util_date.h"
#include "fnmatch.h"

/* types */

#define APACHE_TABLE table
#define APACHE_TIME time_t
#define APACHE_POOL pool
#define APACHE_MODULE module MODULE_VAR_EXPORT

/* variables */

#define APACHE_REQUEST_USER r->connection->user

/* functions */

#define APACHE_PALLOC ap_palloc
#define APACHE_PCALLOC(pool, nbytes) ap_pcalloc(pool, nbytes)
#define APACHE_FNMATCH(pattern, string, flags) \
  ap_fnmatch(pattern, string, flags)
#define APACHE_TABLE_GET(t, key) ap_table_get(t, key)
#define APACHE_TABLE_SET ap_table_set
#define APACHE_TABLE_MAKE ap_make_table
#define APACHE_TABLE_ADD ap_table_add
#define APACHE_TIME_NOW time(NULL)
#define APACHE_PSTRCAT ap_pstrcat
#define APACHE_TIME_FROM_SEC(sec) sec
#define APACHE_PSPRINTF ap_psprintf
#define APACHE_FOPEN(p, filepath, flags) ap_pfopen(p, filepath, flags)
#define APACHE_FCLOSE(p, f) ap_pfclose(p, f)
#define APACHE_BASE64_ENCODE(p, string) ap_uuencode(p, string)
#define APACHE_BASE64_DECODE(p, string) \
  (unsigned char *)ap_uudecode(p, string)
#define APACHE_PARSE_HTTP_DATE ap_parseHTTPdate
#define APACHE_PSTRDUP ap_pstrdup
#define APACHE_LOG_ERROR(x, y, rqst, ...) \
  ap_log_rerror(x, y, rqst, __VA_ARGS__)

/* definitions */

#define APACHE_CMD_REC_TAKE1(name, func, data, override, errmsg) \
  {name, func, data, override, TAKE1, errmsg}

#else

/* APACHE 2 */

/* include */

#include "http_connection.h"
#include "apr_strings.h"
#include "apr_fnmatch.h"
#include "apr_date.h"

/* types */

#define APACHE_TABLE apr_table_t
#define APACHE_TIME apr_time_t
#define APACHE_POOL apr_pool_t
#define APACHE_MODULE module AP_MODULE_DECLARE_DATA

/* variables */

#define APACHE_REQUEST_USER r->user

/* functions */

#define APACHE_PALLOC apr_palloc
#define APACHE_PCALLOC(pool, nbytes) apr_pcalloc(pool, nbytes)
#define APACHE_FNMATCH(pattern, string, flags) \
  apr_fnmatch(pattern, string, flags)
#define APACHE_TABLE_GET(t, key) apr_table_get(t, key)
#define APACHE_TABLE_SET apr_table_set
#define APACHE_TABLE_MAKE apr_table_make
#define APACHE_TABLE_ADD apr_table_add
#define APACHE_TIME_NOW apr_time_now()
#define APACHE_PSTRCAT apr_pstrcat
#define APACHE_TIME_FROM_SEC(sec) apr_time_from_sec(sec)
#define APACHE_PSPRINTF apr_psprintf
#define APACHE_FOPEN(p, filepath, flags) (FILE *)fopen(filepath, flags)
#define APACHE_FCLOSE(p, f) fclose(f)
#define APACHE_BASE64_ENCODE(p, string) \
  ap_pbase64encode(p, string)
#define APACHE_BASE64_DECODE(p, string) \
  ap_pbase64decode(p, (const char *)string)
#define APACHE_PARSE_HTTP_DATE(d) apr_date_parse_http(d)
#define APACHE_PSTRDUP apr_pstrdup
#define APACHE_LOG_ERROR(x, y, rqst, ...) \
  ap_log_rerror(x, y, 0, rqst, __VA_ARGS__)

/* definitions */

#define APACHE_CMD_REC_TAKE1 AP_INIT_TAKE1

#endif

/* ---------------------------------------------------------------------- */

#define PROTOCOL_VERSION "1"
#define AUTH_TYPE "webauth"
#define TESTSTRING "Test"

/* default parameters */

#define DEFAULT_AAAuthService     \
  "https://raven.cam.ac.uk/auth/authenticate.html"
#define DEFAULT_AADescription     NULL
#define DEFAULT_AAResponseTimeout 30
#define DEFAULT_AAClockSkew       30
#define DEFAULT_AAKeyDir          "conf/webauth_keys"
#define DEFAULT_AAMaxSessionLife  7200
#define DEFAULT_AATimeoutMsg      "your existing logon to the site has expired"
#define DEFAULT_AACookieKey       NULL
#define DEFAULT_AACookieName      "Ucam-WebAuth-Session"
#define DEFAULT_AACookiePath      "/"
#define DEFAULT_AACookieDomain    NULL
#define DEFAULT_AAAuthType        "pwd"
#define DEFAULT_AAInteract        NULL
#define DEFAULT_AAFail            NULL
#define DEFAULT_AACancelMsg       NULL
#define DEFAULT_AANoCookieMsg     NULL

/* module configuration structure */

typedef struct {
  char *AAAuthService;
  char *AADescription;
  int   AAResponseTimeout;
  int   AAClockSkew;
  char *AAKeyDir;
  int   AAMaxSessionLife;
  char *AATimeoutMsg;
  char *AACookieKey;
  char *AACookieName;
  char *AACookiePath;
  char *AACookieDomain;
  char *AAAuthType;
  char *AAInteract;
  char *AAFail;
  char *AACancelMsg;
  char *AANoCookieMsg;
} mod_ucam_webauth_cfg;

/* ---------------------------------------------------------------------- */

/* forward declaration of module for ap_get_module_config */

APACHE_MODULE ucam_webauth_module;

/* functions */

static int 
ucam_webauth_handler (request_rec *r);

static void *
create_server_config (APACHE_POOL *p, 
		      server_rec *s);

static char *
get_cgi_param (request_rec *r, 
	       char *parm_name);

static void 
set_cookie (request_rec *r, 
	    char *value, 
	    mod_ucam_webauth_cfg *c);

static char *
SHA1_sign (request_rec *r, 
	   mod_ucam_webauth_cfg *c,  
	   char *data);

static int 
SHA1_sig_verify (request_rec *r, 
		 mod_ucam_webauth_cfg *c, 
		 char *data, 
		 const char *sig);

static int 
RSA_sig_verify (request_rec *r, 
		char *data, 
		char *sig,   
		char *key_path, 
		char *key_id);

static APACHE_TABLE *
unwrap_wls_token (request_rec *r, 
		  char *token_str);

static APACHE_TABLE *
make_cookie_table (request_rec *r, 
		   char *cookie_str);

static char *
get_cookie_str (request_rec *r, 
	        char *cookie_name);

static char *
cookie_check_sig_string (request_rec *r, 
			APACHE_TABLE *cookie);

static char *
wls_response_check_sig_string (request_rec *r, 
			       APACHE_TABLE *wls_response);

static char *
wls_encode (request_rec *r, 
	    char *string);

static char *
wls_decode (request_rec *r, 
	    char *string);

static char *
iso2_time_encode (request_rec *r, 
		  APACHE_TIME t);

static APACHE_TIME 
iso2_time_decode (request_rec *r, 
		  char *t_iso2);

static int 
using_https (request_rec *r);

static char *
full_cookie_name (request_rec *r, 
		  char *cookie_name);

static char *
get_url (request_rec *r);

static char *
error_message (int err);

static char *
no_cookie (request_rec *r, 
	   mod_ucam_webauth_cfg *c);

static char *
auth_cancelled (request_rec *r);

static char *
auth_required (request_rec *r);

/* ---------------------------------------------------------------------- */

static const char *
set_AAAuthService (cmd_parms *cmd, 
		   void *mconfig, 
		   const char *arg) 

{

  mod_ucam_webauth_cfg *cfg;
  
  if (cmd->path != NULL) {
    cfg = (mod_ucam_webauth_cfg *)mconfig;
  } else {
    cfg = (mod_ucam_webauth_cfg *) 
      ap_get_module_config(cmd->server->module_config, &ucam_webauth_module);
  }

  cfg->AAAuthService = (char *)arg;
  
  return NULL;

}

/* --- */

static const char *
set_AADescription(cmd_parms *cmd, 
		  void *mconfig, 
		  const char *arg) 

{

  mod_ucam_webauth_cfg *cfg;
  
  if (cmd->path != NULL) {
    cfg = (mod_ucam_webauth_cfg *)mconfig;
  } else {
    cfg = (mod_ucam_webauth_cfg *) 
      ap_get_module_config(cmd->server->module_config, &ucam_webauth_module);
  }

  cfg->AADescription = (char *)arg;
  return NULL;
}

/* --- */

static const char *
set_AAResponseTimeout(cmd_parms *cmd, 
		      void *mconfig, 
		      const char *arg) 
     
{

  mod_ucam_webauth_cfg *cfg;
 
  if (cmd->path != NULL) {
    cfg = (mod_ucam_webauth_cfg *)mconfig;
  } else {
    cfg = (mod_ucam_webauth_cfg *) 
      ap_get_module_config(cmd->server->module_config, &ucam_webauth_module);
  }

  cfg->AAResponseTimeout = atoi(arg);
  if (cfg->AAResponseTimeout < 0) 
    return "AAResponseTimeout must be a positive number";
  return NULL;

}

/* --- */

static const char *
set_AAClockSkew(cmd_parms *cmd, 
		void *mconfig, 
		const char *arg) 

{

  mod_ucam_webauth_cfg *cfg;
 
  if (cmd->path != NULL) {
    cfg = (mod_ucam_webauth_cfg *)mconfig;
  } else {
    cfg = (mod_ucam_webauth_cfg *) 
      ap_get_module_config(cmd->server->module_config, &ucam_webauth_module);
  }

  cfg->AAClockSkew = atoi(arg);
  return NULL;

}

/* --- */

static const char *
set_AAKeyDir(cmd_parms *cmd, 
	     void *mconfig, 
	     const char *arg) 

{

  mod_ucam_webauth_cfg *cfg;
 
  if (cmd->path != NULL) {
    cfg = (mod_ucam_webauth_cfg *)mconfig;
  } else {
    cfg = (mod_ucam_webauth_cfg *) 
      ap_get_module_config(cmd->server->module_config, &ucam_webauth_module);
  }

  cfg->AAKeyDir = (char *)arg;
  return NULL;

}

/* --- */

static const char *
set_AAMaxSessionLife(cmd_parms *cmd, 
		     void *mconfig, 
		     const char *arg) 

{

  mod_ucam_webauth_cfg *cfg;
 
  if (cmd->path != NULL) {
    cfg = (mod_ucam_webauth_cfg *)mconfig;
  } else {
    cfg = (mod_ucam_webauth_cfg *) 
      ap_get_module_config(cmd->server->module_config, &ucam_webauth_module);
  }

  cfg->AAMaxSessionLife = atoi(arg);
  if (cfg->AAMaxSessionLife < 0) 
    return "AAMaxSessionLife must be a positive number";
  return NULL;

}

/* --- */

static const char *
set_AATimeoutMsg(cmd_parms *cmd, 
		 void *mconfig, 
		 const char *arg) 

{

  mod_ucam_webauth_cfg *cfg;
 
  if (cmd->path != NULL) {
    cfg = (mod_ucam_webauth_cfg *)mconfig;
  } else {
    cfg = (mod_ucam_webauth_cfg *) 
      ap_get_module_config(cmd->server->module_config, &ucam_webauth_module);
  }

  cfg->AATimeoutMsg = (char *)arg;
  return NULL;

}

/* --- */

static const char *
set_AACookieKey(cmd_parms *cmd, 
		void *mconfig, 
		const char *arg) 

{

  mod_ucam_webauth_cfg *cfg;
  if (arg == NULL) return "AACookieKey not defined";
 
  if (cmd->path != NULL) {
    cfg = (mod_ucam_webauth_cfg *)mconfig;
  } else {
    cfg = (mod_ucam_webauth_cfg *) 
      ap_get_module_config(cmd->server->module_config, &ucam_webauth_module);
  }

  cfg->AACookieKey = (char *)arg;
  return NULL;

}

/* --- */

static const char *
set_AACookieName(cmd_parms *cmd, 
		 void *mconfig, 
		 const char *arg) 

{

  mod_ucam_webauth_cfg *cfg;
 
  if (cmd->path != NULL) {
    cfg = (mod_ucam_webauth_cfg *)mconfig;
  } else {
    cfg = (mod_ucam_webauth_cfg *) 
      ap_get_module_config(cmd->server->module_config, &ucam_webauth_module);
  }

  cfg->AACookieName = (char *)arg;
  return NULL;

}

/* --- */

static const char *
set_AACookiePath(cmd_parms *cmd, 
		 void *mconfig, 
		 const char *arg) 

{

  mod_ucam_webauth_cfg *cfg;
 
  if (cmd->path != NULL) {
    cfg = (mod_ucam_webauth_cfg *)mconfig;
  } else {
    cfg = (mod_ucam_webauth_cfg *) 
      ap_get_module_config(cmd->server->module_config, &ucam_webauth_module);
  }

  cfg->AACookiePath = (char *)arg;
  return NULL;

}

/* --- */

static const char *
set_AACookieDomain(cmd_parms *cmd, 
		   void *mconfig, 
		   const char *arg) 

{

  mod_ucam_webauth_cfg *cfg;
 
  if (cmd->path != NULL) {
    cfg = (mod_ucam_webauth_cfg *)mconfig;
  } else {
    cfg = (mod_ucam_webauth_cfg *) 
      ap_get_module_config(cmd->server->module_config, &ucam_webauth_module);
  }

  cfg->AACookieDomain = (char *)arg;
  return NULL;

}

/* --- */

static const char *
set_AAAuthType(cmd_parms *cmd, 
	       void *mconfig, 
	       const char *arg) 

{

  mod_ucam_webauth_cfg *cfg;
 
  if (cmd->path != NULL) {
    cfg = (mod_ucam_webauth_cfg *)mconfig;
  } else {
    cfg = (mod_ucam_webauth_cfg *) 
      ap_get_module_config(cmd->server->module_config, &ucam_webauth_module);
  }

  cfg->AAAuthType = (char *)arg;
  return NULL;

}

/* --- */

static const char *
set_AAInteract(cmd_parms *cmd, 
	       void *mconfig, 
	       const char *arg) 

{

  mod_ucam_webauth_cfg *cfg;
 
  if (cmd->path != NULL) {
    cfg = (mod_ucam_webauth_cfg *)mconfig;
  } else {
    cfg = (mod_ucam_webauth_cfg *) 
      ap_get_module_config(cmd->server->module_config, &ucam_webauth_module);
  }

  cfg->AAInteract = (char *)arg;
  return NULL;

}

/* --- */

static const char *
set_AAFail(cmd_parms *cmd, 
	   void *mconfig, 
	   const char *arg) 

{

  mod_ucam_webauth_cfg *cfg;
 
  if (cmd->server == NULL) {
    cfg = (mod_ucam_webauth_cfg *)mconfig;
  } else {
    cfg = (mod_ucam_webauth_cfg *) 
      ap_get_module_config(cmd->server->module_config, &ucam_webauth_module);
  }

  cfg->AAFail = (char *)arg;
  return NULL;

}

/* --- */

static const char *
set_AACancelMsg(cmd_parms *cmd, 
		void *mconfig, 
		const char *arg) 

{

  mod_ucam_webauth_cfg *cfg;
 
  if (cmd->path != NULL) {
    cfg = (mod_ucam_webauth_cfg *)mconfig;
  } else {
    cfg = (mod_ucam_webauth_cfg *) 
      ap_get_module_config(cmd->server->module_config, &ucam_webauth_module);
  }

  cfg->AACancelMsg = (char *)arg;
  return NULL;

}

/* --- */

static const char *
set_AANoCookieMsg(cmd_parms *cmd, 
		  void *mconfig, 
		  const char *arg) 

{

  mod_ucam_webauth_cfg *cfg;
 
  if (cmd->path != NULL) {
    cfg = (mod_ucam_webauth_cfg *)mconfig;
  } else {
    cfg = (mod_ucam_webauth_cfg *) 
      ap_get_module_config(cmd->server->module_config, &ucam_webauth_module);
  }

  cfg->AANoCookieMsg = (char *)arg;
  return NULL;

}

/* ---------------------------------------------------------------------- */

/* configuration directives table */

static const command_rec config_commands[] = {

  APACHE_CMD_REC_TAKE1("AAAuthService", 
		       set_AAAuthService, 
		       NULL, 
		       RSRC_CONF | OR_AUTHCFG,
		       "Raven authentication server logon site"),

  APACHE_CMD_REC_TAKE1("AADescription", 
		       set_AADescription, 
		       NULL, 
		       RSRC_CONF | OR_AUTHCFG,
		       "site description"),

  APACHE_CMD_REC_TAKE1("AAResponseTimeout", 
		       set_AAResponseTimeout, 
		       NULL, 
		       RSRC_CONF | OR_AUTHCFG,
		       "timeout for response messages"),

  APACHE_CMD_REC_TAKE1("AAClockSkew", 
		       set_AAClockSkew, 
		       NULL, 
		       RSRC_CONF | OR_AUTHCFG,
		       "max server/client clock difference"),

  APACHE_CMD_REC_TAKE1("AAKeyDir", 
		       set_AAKeyDir, 
		       NULL, 
		       RSRC_CONF | OR_AUTHCFG,
		       "directory containing WLS keys"),

  APACHE_CMD_REC_TAKE1("AAMaxSessionLife", 
		       set_AAMaxSessionLife, 
		       NULL, 
		       RSRC_CONF | OR_AUTHCFG,
		       "timeout for WAA session"),

  APACHE_CMD_REC_TAKE1("AATimeoutMessage", 
		       set_AATimeoutMsg, 
		       NULL, 
		       RSRC_CONF | OR_AUTHCFG,
		       "message on WAA session timeout"),

  APACHE_CMD_REC_TAKE1("AACookieKey", 
		       set_AACookieKey, 
		       NULL, 
		       RSRC_CONF | OR_AUTHCFG,
		       "key for session cookie"),

  APACHE_CMD_REC_TAKE1("AACookieName", 
		       set_AACookieName, 
		       NULL, 
		       RSRC_CONF | OR_AUTHCFG,
		       "name for session cookie"),

  APACHE_CMD_REC_TAKE1("AACookiePath", 
		       set_AACookiePath, 
		       NULL, 
		       RSRC_CONF | OR_AUTHCFG,
		       "path prefix for session cookie"),

  APACHE_CMD_REC_TAKE1("AACookieDomain", 
		       set_AACookieDomain, 
		       NULL, 
		       RSRC_CONF | OR_AUTHCFG,
		       "domain for session cookie"),

  APACHE_CMD_REC_TAKE1("AAAuthType", 
		       set_AAAuthType, 
		       NULL, 
		       RSRC_CONF | OR_AUTHCFG,
		       "authentication type required"),

  APACHE_CMD_REC_TAKE1("AAInteract", 
		       set_AAInteract, 
		       NULL, 
		       RSRC_CONF | OR_AUTHCFG,
		       "force re-authentication?"),

  APACHE_CMD_REC_TAKE1("AAFail", 
		       set_AAFail, 
		       NULL, 
		       RSRC_CONF | OR_AUTHCFG,
		       "fail at WLS and, don't return?"),

  APACHE_CMD_REC_TAKE1("AACancelMsg", 
		       set_AACancelMsg, 
		       NULL, 
		       RSRC_CONF | OR_AUTHCFG,
		       "custom error for authentication cancelled"),

  APACHE_CMD_REC_TAKE1("AANoCookieMsg", 
		       set_AANoCookieMsg, 
		       NULL, 
		       RSRC_CONF | OR_AUTHCFG,
		       "custom error for no cookie"),

  {NULL}

};

/* ---------------------------------------------------------------------- */

/* create per-directory config */
 
static void *
create_dir_config(APACHE_POOL *p, 
		  char *path) 

{

  mod_ucam_webauth_cfg *cfg = 
    (mod_ucam_webauth_cfg *)APACHE_PCALLOC(p, sizeof(mod_ucam_webauth_cfg));
  cfg->AAAuthService = NULL;
  cfg->AADescription = NULL;
  cfg->AAResponseTimeout = -1;
  cfg->AAClockSkew = -1;
  cfg->AAKeyDir = NULL;
  cfg->AAMaxSessionLife = -1;
  cfg->AATimeoutMsg = NULL;
  cfg->AACookieKey = NULL;
  cfg->AACookieName = NULL;
  cfg->AACookiePath = NULL;
  cfg->AACookieDomain = NULL;
  cfg->AAAuthType = NULL;
  cfg->AAInteract = NULL;;
  cfg->AAFail = NULL;
  cfg->AACancelMsg = NULL;
  cfg->AANoCookieMsg = NULL;
  return (void *)cfg;

}

/* --- */

/* create per-server config */

static void *
create_server_config(APACHE_POOL *p, 
		     server_rec *s) 

{

  mod_ucam_webauth_cfg *cfg = 
    (mod_ucam_webauth_cfg *)APACHE_PCALLOC(p, sizeof(mod_ucam_webauth_cfg));
  cfg->AAAuthService = DEFAULT_AAAuthService;
  cfg->AADescription = DEFAULT_AADescription;
  cfg->AAResponseTimeout = DEFAULT_AAResponseTimeout;
  cfg->AAClockSkew = DEFAULT_AAClockSkew;
  cfg->AAKeyDir = DEFAULT_AAKeyDir;
  cfg->AAMaxSessionLife = DEFAULT_AAMaxSessionLife;
  cfg->AATimeoutMsg = DEFAULT_AATimeoutMsg;
  cfg->AACookieKey = DEFAULT_AACookieKey;
  cfg->AACookieName = DEFAULT_AACookieName;
  cfg->AACookiePath = DEFAULT_AACookiePath;
  cfg->AACookieDomain = DEFAULT_AACookieDomain;
  cfg->AAAuthType = DEFAULT_AAAuthType;
  cfg->AAInteract = DEFAULT_AAInteract;
  cfg->AAFail = DEFAULT_AAFail;
  cfg->AACancelMsg = DEFAULT_AACancelMsg;
  cfg->AANoCookieMsg = DEFAULT_AANoCookieMsg;
  return (void *)cfg;

}

/* ***********************************************

static int 
ucam_webauth_authz(request_rec *r) 

{

  if (r->main != NULL) {
    return OK;
  }

  return DECLINED;

}

************************************************ */

/* --- */

/* authentication handler */
   
static int  
ucam_webauth_handler(request_rec *r) 
     
{
  
  mod_ucam_webauth_cfg *server_c = (mod_ucam_webauth_cfg *) 
    ap_get_module_config(r->server->module_config, &ucam_webauth_module);
  mod_ucam_webauth_cfg *c = (mod_ucam_webauth_cfg *) 
    ap_get_module_config(r->per_dir_config, &ucam_webauth_module);
  char *old_cookie_str;
  char *timeout_msg = NULL;
  APACHE_TABLE *old_cookie;
  APACHE_TIME issue, expire, now;
  char *token_str;
  APACHE_TABLE *response_ticket;
  char *msg, *status;
  int expiry, response_ticket_life;
  char *session_ticket;
  char *request;
  char *this_url;
  int sig_verify_result;
  const char *response_url;

  /****
  if (r->main != NULL) {
    // *** use ucam_webauth_authz ***
    return OK;
  }
  ****/

  if (strcasecmp(ap_auth_type(r), AUTH_TYPE) != 0) return DECLINED;
  
  APACHE_LOG_ERROR
    (APLOG_MARK, APLOG_NOERRNO | APLOG_NOTICE, r,
     "Apache Raven AA handler version " VERSION " started for %s", r->uri);
  
  if (r->method_number == M_POST)
    APACHE_LOG_ERROR
      (APLOG_MARK, APLOG_NOERRNO | APLOG_WARNING, r,
       "ApacheAA hander invoked for POST request, "
       "which it doesn't really support");

  if (c->AAAuthService == NULL) 
    c->AAAuthService = server_c->AAAuthService;
  if (c->AADescription == NULL) 
    c->AADescription = server_c->AADescription;
  if (c->AAResponseTimeout == -1) 
    c->AAResponseTimeout = server_c->AAResponseTimeout;
  if (c->AAClockSkew == -1) 
    c->AAClockSkew = server_c->AAClockSkew;
  if (c->AAKeyDir == NULL) 
    c->AAKeyDir = server_c->AAKeyDir;
  if (c->AAMaxSessionLife == -1) 
    c->AAMaxSessionLife = server_c->AAMaxSessionLife;
  if (c->AATimeoutMsg == NULL) 
    c->AATimeoutMsg = server_c->AATimeoutMsg;
  if (c->AACookieKey == NULL) 
    c->AACookieKey = server_c->AACookieKey;
  if (c->AACookieName == NULL) 
    c->AACookieName = server_c->AACookieName;
  if (c->AACookiePath == NULL) 
    c->AACookiePath = server_c->AACookiePath;
  if (c->AACookieDomain == NULL) 
    c->AACookieDomain = server_c->AACookieDomain;
  if (c->AAAuthType == NULL) 
    c->AAAuthType = server_c->AAAuthType;
  if (c->AAInteract == NULL) 
    c->AAInteract = server_c->AAInteract;
  if (c->AAFail == NULL) 
    c->AAFail = server_c->AAFail;
  if (c->AACancelMsg == NULL) 
    c->AACancelMsg = server_c->AACancelMsg;
  if (c->AANoCookieMsg == NULL) 
    c->AANoCookieMsg = server_c->AANoCookieMsg;

  if (APACHE_FNMATCH(APACHE_PSTRCAT(r->pool, c->AACookiePath, "*", NULL),
		     r->parsed_uri.path,
		     0/*APR_FNM_PATHNAME*/) == FNM_NOMATCH) {
    APACHE_LOG_ERROR
      (APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r,
       "AACookiePath %s is not a prefix of %s", 
       c->AACookiePath, r->parsed_uri.path);
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  
  /* FIRST: see if we already have authentication data stored in a
     cookie. Note that if the stored status isn't 200 (OK) then we
     need to report the failure here and we destroy the cookie so
     that if we come back through here again we will fall through
     and repeat the authentication */
       
  APACHE_LOG_ERROR
    (APLOG_MARK, APLOG_NOERRNO | APLOG_NOTICE, r,
     "entering FIRST stage...");

  old_cookie_str = get_cookie_str(r, full_cookie_name(r, c->AACookieName));

  if (old_cookie_str == NULL) 
    APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, r,
		     "no existing authentication cookie found");

  if (old_cookie_str != NULL && strcmp(old_cookie_str, TESTSTRING) != 0) {
    APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, r,
		     "found existing authentication cookie");

    ap_unescape_url(old_cookie_str);

    APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		     "cookie str = %s", old_cookie_str);
    
    old_cookie = make_cookie_table(r, old_cookie_str);
    
    /* check cookie signature */

    if (SHA1_sig_verify(r, c, cookie_check_sig_string(r, old_cookie), 
			(char *)APACHE_TABLE_GET(old_cookie, "sig"))) {

      APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, r,
		       "session cookie signature valid");
      
      if (strcmp((char *)APACHE_TABLE_GET(old_cookie, "status"), "410") == 0) {
	if (c->AACancelMsg != NULL) {
	  ap_custom_response(r, HTTP_FORBIDDEN, c->AACancelMsg);
	} 
	else {
	  ap_custom_response(r, HTTP_FORBIDDEN, auth_cancelled(r));
	}
	set_cookie(r, NULL, c);
	
	APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_WARNING, r,
			 "status = 410, access forbidden");
	
	return HTTP_FORBIDDEN;
      }

      if (strcmp((char *)APACHE_TABLE_GET(old_cookie, "status"), "200") != 0) {
	APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r,
			 "cookie error, status = %s, %s",
			 APACHE_TABLE_GET(old_cookie, "status"),
			 APACHE_TABLE_GET(old_cookie, "msg"));
	set_cookie(r, NULL, c);
	return HTTP_INTERNAL_SERVER_ERROR;
      }
      
      // session cookie timeout check
      
      issue = iso2_time_decode
	(r,(char *)APACHE_TABLE_GET(old_cookie, "issue"));
      expire = iso2_time_decode
	(r,(char *)APACHE_TABLE_GET(old_cookie, "expire"));

      if (issue == -1) {
	APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r,
			 "session cookie issue date incorrect length");
	return HTTP_INTERNAL_SERVER_ERROR;
      }
      if (expire == -1) {
	APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r,
			 "session cookie expire date incorrect length");
	return HTTP_INTERNAL_SERVER_ERROR;
      }

      now = APACHE_TIME_NOW;
      
      APACHE_LOG_ERROR
	(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
	 "issue = %s, expire = %s", 
	 (char *)APACHE_TABLE_GET(old_cookie, "issue"), 
	 (char *)APACHE_TABLE_GET(old_cookie, "expire"));
      
      APACHE_LOG_ERROR
	(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
	 "now = %s, issue = %s, expire = %s", 
	 iso2_time_encode(r, now), 
	 iso2_time_encode(r, issue), iso2_time_encode(r, expire));

      if (issue > now) {
	APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r,
			 "session cookie has issue date in the future");
	return HTTP_INTERNAL_SERVER_ERROR;
      } else if (now >= expire) {
	APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_NOTICE, r,
			 "session cookie has timed out");
	timeout_msg = c->AATimeoutMsg;
      } else {
	APACHE_REQUEST_USER = 
	  (char *)APACHE_TABLE_GET(old_cookie, "principal");
	APACHE_LOG_ERROR
	  (APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
	   "user = %s", APACHE_REQUEST_USER);
	APACHE_TABLE_ADD(r->subprocess_env, 
			 "AAISSUE", 
			 APACHE_TABLE_GET(old_cookie, "issue"));
	APACHE_TABLE_ADD(r->subprocess_env, 
			 "AAEXPIRE", 
			 APACHE_TABLE_GET(old_cookie, "expire"));
	APACHE_TABLE_ADD(r->subprocess_env, 
			 "AAID", 
			 APACHE_TABLE_GET(old_cookie, "id"));
	APACHE_TABLE_ADD(r->subprocess_env, 
			 "AAPRINCIPAL", 
			 APACHE_TABLE_GET(old_cookie, "principal"));
	APACHE_TABLE_ADD(r->subprocess_env, 
			 "AAAUTH", 
			 APACHE_TABLE_GET(old_cookie, "auth"));
	APACHE_TABLE_ADD(r->subprocess_env, 
			 "AASSO", 
			 APACHE_TABLE_GET(old_cookie, "sso"));

	ap_custom_response(r, HTTP_UNAUTHORIZED, auth_required(r));

	APACHE_LOG_ERROR
	  (APLOG_MARK, APLOG_NOERRNO | APLOG_NOTICE, r,
	   "successful authentication for %s", APACHE_REQUEST_USER);

	return OK;
      }

    } else {

      APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r,
		       "session cookie signature invalid");
      set_cookie(r, NULL, c);
      return HTTP_INTERNAL_SERVER_ERROR;

    }

  }  

  /* SECOND: Look to see if we are being invoked as the callback from 
     the WLS. If so, validate the response, check that the session
     cookie already exists with a test value (because otherwise we
     probably don't have cookies enabled), set it, and redirect back to
     the original URL to clear the browser's location bar of the WLS
     response */
  
  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_NOTICE, r,
		   "entering SECOND stage...");
  
  token_str = get_cgi_param(r, "WLS-Response");
  
  if (token_str != NULL) {
    APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, r,
		     "found WLS token");

    APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		     "token data = %s", token_str);

    /* Check that cookie actually exists because it should have
      been created previously and if it's not there we'll probably
      end up in a redirect loop */

    APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, r,
		      "searching for cookie %s", c->AACookieName);

    old_cookie_str = get_cookie_str(r, full_cookie_name(r, c->AACookieName));
    if (old_cookie_str == NULL) {
      APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r,
		       "browser not accepting session cookie");

      if (c->AANoCookieMsg != NULL) {
	ap_custom_response(r, HTTP_INTERNAL_SERVER_ERROR, c->AANoCookieMsg);
      } else {
	ap_custom_response(r, HTTP_INTERNAL_SERVER_ERROR, no_cookie(r, c));
      }
      return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* unwrap WLS token */
    
    ap_unescape_url(token_str);
    response_ticket = unwrap_wls_token(r, token_str);
    
    /* check that the URL in the token is plausable 
       (strip URL from cookie str, get this from request?) */

    this_url = get_url(r);
    response_url = APACHE_TABLE_GET(response_ticket, "url");
    response_url = ap_getword(r->pool, &response_url, '?');

    if (strcmp(response_url, this_url) != 0) {
      APACHE_LOG_ERROR
	(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r,
	 "URL in response_token doesn't match this URL - %s != %s",
	 response_url, this_url);

      return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* from now on we can (probably) safely redirect to the URL in the 
       token so that we get 'clean' error messages */                
 
    msg = "";
    status = "200";

    sig_verify_result = 
      RSA_sig_verify(r, 
		     wls_response_check_sig_string(r, response_ticket),
		     (char *)APACHE_TABLE_GET(response_ticket, "sig"), 
		     c->AAKeyDir,
		     (char *)APACHE_TABLE_GET(response_ticket, "kid"));
    /* RETURNS
        -1 : verification error
         0 : UNsuccessful verification
         1 : successful verifcation
         2 : error opening public key file
         3 : error reading public key */

    /* unsucessful verification */

    if (sig_verify_result == 0) {

      msg = "missing or invalid signature in authentication service reply";
      status = "600";
      APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r, msg);

    } else if (sig_verify_result == 1) {

      /* successful verification */
      
      if (strcmp((char *)APACHE_TABLE_GET(response_ticket, "ver"), 
		 PROTOCOL_VERSION) != 0) {
	msg = "wrong protocol version in authentication service reply";
	status = "600";
	APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r, msg);

      } else if (strcmp(APACHE_TABLE_GET(response_ticket, "status"), 
			"200") != 0) {
	msg = error_message(atoi(APACHE_TABLE_GET(response_ticket, "status")));
	if (APACHE_TABLE_GET(response_ticket, "msg") != NULL) {
	  msg = APACHE_PSTRCAT(r->pool, msg, 
			       APACHE_TABLE_GET(response_ticket, "msg"), NULL);
	}
	status = (char*)APACHE_TABLE_GET(response_ticket, "status");
	APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r, msg);

      } else {
	APACHE_TIME now = APACHE_TIME_NOW;
	APACHE_TIME issue = 
	  iso2_time_decode(r, 
			   (char *)APACHE_TABLE_GET(response_ticket, "issue"));
	if (issue < 0) {
	  msg = "unable to read issue time in authentication service reply";
	  status = "600";
	  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r, msg);
	} else {
	  if (issue > now + APACHE_TIME_FROM_SEC(c->AAClockSkew)) {
	    msg = "authentication service reply issued in the future";
	    status = "600";
	    APACHE_LOG_ERROR
	      (APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r, msg);
	  } else if (now - APACHE_TIME_FROM_SEC(c->AAClockSkew) > 
		     issue + APACHE_TIME_FROM_SEC(c->AAResponseTimeout)) {
	    msg = "stale authentication service reply issued at";
	    status = "600";
	    APACHE_LOG_ERROR
	      (APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r,
	       "stale authentication reply issued at %s", 
	       APACHE_TABLE_GET(response_ticket, "issue"));
	  } else {
	    APACHE_LOG_ERROR
	      (APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, r,
	       "validated WLS token ID %s", 
	       APACHE_TABLE_GET(response_ticket, "id"));
	  }
	}
      }

    } else if (sig_verify_result == 2) {
      APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_ALERT, r, 
		       "error opening public key file");
      return HTTP_INTERNAL_SERVER_ERROR;

    } else if (sig_verify_result == 3) {
      APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_ALERT, r, 
		       "error reading public key file");
      return HTTP_INTERNAL_SERVER_ERROR;

    } else {
      APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_ALERT, r, 
		 "signature verification error");
      return HTTP_INTERNAL_SERVER_ERROR;

    }

    /* calculate session expiry */

    expiry = c->AAMaxSessionLife;
    response_ticket_life = atoi(APACHE_TABLE_GET(response_ticket, "life"));
    if (APACHE_TABLE_GET(response_ticket, "life") != NULL && 
	response_ticket_life < expiry)
      expiry = response_ticket_life;

    APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		     "expiry = %d", expiry);

    if (expiry <= 0) {
      APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, r,
		     "session expiry time less that one second");
      return HTTP_INTERNAL_SERVER_ERROR;
    }
     
    /* set new session ticket (cookie) */
    
    session_ticket = APACHE_PSTRCAT
      (r->pool,
       APACHE_TABLE_GET(response_ticket, "ver"), "!",
       status, "!",
       msg, "!",
       iso2_time_encode(r, APACHE_TIME_NOW), "!",
       iso2_time_encode(r, APACHE_TIME_NOW + APACHE_TIME_FROM_SEC(expiry)),"!",
       APACHE_TABLE_GET(response_ticket, "id"), "!",
       APACHE_TABLE_GET(response_ticket, "principal"), "!",
       APACHE_TABLE_GET(response_ticket, "auth"), "!",
       APACHE_TABLE_GET(response_ticket, "sso"), "!",
       APACHE_TABLE_GET(response_ticket, "params"), 
       NULL);

    session_ticket = APACHE_PSTRCAT
      (r->pool, 
       session_ticket, "!1!", 
       SHA1_sign(r, c, session_ticket), 
       NULL);
 
   session_ticket = ap_escape_uri(r->pool, session_ticket);

   APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		    "session ticket = %s", session_ticket);
   
   set_cookie(r, session_ticket, c);

   /* redirect */

   APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_NOTICE, r,
		    "issuing redirect to original URL");
   
   APACHE_TABLE_SET(r->headers_out, 
		    "Location", 
		    APACHE_TABLE_GET(response_ticket, "url"));

   return (r->method_number == M_GET) ? HTTP_MOVED_TEMPORARILY : HTTP_SEE_OTHER;

  }
  
  /* THIRD: send a request to the WLS. Also set a test value cookie so
   * we can test that it's still available when we get back */

  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_NOTICE, r,
		   "entering THIRD stage..."); 
  
  request = APACHE_PSTRCAT(r->pool,
			   "ver=", PROTOCOL_VERSION,
			   "&url=", get_url(r),
			   NULL);
  if (c->AADescription != NULL) {
    request = APACHE_PSTRCAT(r->pool, 
			     request, 
			     "&desc=", c->AADescription, 
			     NULL);
  }
  if (timeout_msg != NULL) {
    request = APACHE_PSTRCAT(r->pool, 
			     request, 
			     "&msg=", 
			     c->AATimeoutMsg, 
			     NULL);
  }
  if (c->AAFail != NULL) {
    request = APACHE_PSTRCAT(r->pool, request, "&fail=yes", NULL);
  }
  if (c->AAClockSkew != 0) {
    request = APACHE_PSTRCAT(r->pool, 
			     request,
			     "&date=", 
			     iso2_time_encode(r, APACHE_TIME_NOW),
			     "&skew=", 
			     APACHE_PSPRINTF(r->pool, "%d", c->AAClockSkew), 
			     NULL);
  }
  request = APACHE_PSTRCAT(r->pool,
			   c->AAAuthService, 
			   "?",
			   ap_escape_uri(r->pool, request), 
			   NULL);

  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		   "request = %s", request);
  
  APACHE_TABLE_SET(r->headers_out, "Location", request);
  set_cookie(r, TESTSTRING, c);

  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_NOTICE, r,
		   "redirecting to Raven login server");

  return (r->method_number == M_GET) ? HTTP_MOVED_TEMPORARILY : HTTP_SEE_OTHER;

  /* (phew!) */

}

/* --- */

/* get CGI parameter */

static char *
get_cgi_param(request_rec *r, 
	      char *parm_name) 

{

  const char *data = r->args;
  const char *pair;

  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		   "get_cgi_param, r->args = %s", data);
  
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

/* set cookie */

static void 
set_cookie(request_rec *r, 
	   char *value, 
	   mod_ucam_webauth_cfg *c) 

{

  char *cookie;

  // if NULL value supplied then delete cookie by setting expiry in the past

  if (value == NULL) {
    cookie = APACHE_PSTRCAT(r->pool, 
			    full_cookie_name(r, c->AACookieName),
			    "= ; path=",
			    c->AACookiePath, 
			    ";expires=Thu, 21-Oct-1982 00:00:00 GMT", NULL);
  } else {
    cookie = APACHE_PSTRCAT(r->pool, 
			    full_cookie_name(r, c->AACookieName), 
			    "=", value,
			    "; path=", 
			    c->AACookiePath, NULL);
  }

  if (c->AACookieDomain != NULL) {
    cookie = APACHE_PSTRCAT(r->pool, 
			    cookie, 
			    ";domain=", 
			    c->AACookieDomain, NULL);
  }

  if (using_https(r)) {
    cookie = APACHE_PSTRCAT(r->pool, cookie, "; secure", NULL);
  }

  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		   "set_cookie str = %s", cookie);

  APACHE_TABLE_ADD(r->err_headers_out, "Set-Cookie", cookie);
}


/* --- */

/* SHA1 sign */

static char *
SHA1_sign(request_rec *r, 
	  mod_ucam_webauth_cfg *c,  
	  char *data) 

{

  unsigned char *new_sig = 
    (unsigned char *)APACHE_PCALLOC(r->pool, EVP_MAX_MD_SIZE + 1);
  unsigned int sig_len;

  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		    "making sig with data = %s", data);

  HMAC(EVP_sha1(), c->AACookieKey, sizeof(c->AACookieKey), 
       (const unsigned char *)data, sizeof(data), new_sig, &sig_len);
  new_sig = (unsigned char*)wls_encode(r, (char *)new_sig);

  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		    "new sig = %s", new_sig);
  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		    "new sig length = %d", sig_len);

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
    (unsigned char *)APACHE_PCALLOC(r->pool, EVP_MAX_MD_SIZE + 1);
  //unsigned char new_sig[EVP_MAX_MD_SIZE];
  unsigned int sig_len;

  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		   "verifying sig: %s", data);
  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		   "sig size = %d", sizeof(data));

  HMAC(EVP_sha1(), c->AACookieKey, sizeof(c->AACookieKey), 
       (const unsigned char *)data, sizeof(data), new_sig, &sig_len);
  new_sig = (unsigned char*)wls_encode(r, (char *)new_sig);

  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		   "new sig = %s", new_sig);
  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		   "new sig length = %d", sig_len);

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

  /* RETURNS
      -1 : verification error
       0 : UNsuccessful verification
       1 : successful verifcation
       2 : error opening public key file
       3 : error reading public key */

  unsigned char* decoded_sig;
  int sig_length;
  int result;
  char *key_full_path = 
    ap_server_root_relative
    (r->pool, 
     ap_make_full_path(r->pool, 
		       key_path, 
		       APACHE_PSTRCAT(r->pool, "pubkey", key_id, NULL)));
  FILE *key_file;
  char *digest = APACHE_PALLOC(r->pool, 21);
  RSA *public_key;
  int openssl_error;

  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		   "RSA_sig_verify...");

  SHA1((const unsigned char *)data, strlen(data), (unsigned char *)digest);
  
  key_file = (FILE *)APACHE_FOPEN(r->pool, key_full_path, "r");
  if (key_file == NULL) {
    APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_ALERT, r,
		     "error opening file: %s", key_full_path);
    return 2;
  }

  public_key = (RSA *)PEM_read_RSAPublicKey(key_file, NULL, NULL, NULL);
  APACHE_FCLOSE(r->pool, key_file);
  
  if (public_key == NULL) return 3;

  decoded_sig = (unsigned char *)wls_decode(r, sig);
  sig_length = 128;

  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		    "digest length = %d", strlen(digest));
  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		    "sig length = %d", sig_length);

  result = RSA_verify(NID_sha1, 
		      (unsigned char *)digest, 
		      20, 
		      decoded_sig, 
		      sig_length, 
		      public_key);

  openssl_error = ERR_get_error();
  if (openssl_error) {
    APACHE_LOG_ERROR
      (APLOG_MARK, APLOG_NOERRNO | APLOG_ALERT, r,
       "last OpenSSL error = %s", ERR_error_string(openssl_error, NULL));
  }

  APACHE_LOG_ERROR
    (APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
     "RSA verify result = %d", result);

  RSA_free(public_key);
  
  return result;

}

/* --- */

static APACHE_TABLE *
unwrap_wls_token(request_rec *r, 
		 char *token_str) 

{

  const char *pair;
  APACHE_TABLE *wls_token;
  pair = token_str;
  wls_token = (APACHE_TABLE *)APACHE_TABLE_MAKE(r->pool, 11);
  
  APACHE_TABLE_ADD(wls_token, 
		   "ver", 
		   (const char *)ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(wls_token, 
		   "status", 
		   (const char *)ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(wls_token, 
		   "msg", 
		   (const char *)ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(wls_token, 
		   "issue", 
		   (const char *)ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(wls_token, 
		   "id", 
		   (const char *)ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(wls_token, 
		   "url", 
		   (const char *)ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(wls_token, 
		   "principal", 
		   (const char *)ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(wls_token, 
		   "auth", 
		   (const char *)ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(wls_token, 
		   "sso", 
		   (const char *)ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(wls_token, 
		   "life", 
		   (const char *)ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(wls_token, 
		   "params", 
		   (const char *)ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(wls_token, 
		   "kid", 
		   (const char *)ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(wls_token, 
		   "sig", 
		   (const char *)ap_getword_nulls(r->pool, &pair, '!'));

  return wls_token;

}

/* --- */

static APACHE_TABLE *
make_cookie_table(request_rec *r, 
		  char *cookie_str) 

{

  const char *pair;
  APACHE_TABLE *cookie;
  pair = cookie_str;
  cookie = (APACHE_TABLE *)APACHE_TABLE_MAKE(r->pool, 11);

  APACHE_TABLE_ADD(cookie, "ver", ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(cookie, "status", ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(cookie, "msg", ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(cookie, "issue", ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(cookie, "expire", ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(cookie, "id", ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(cookie, "principal", ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(cookie, "auth", ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(cookie, "sso", ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(cookie, "params", ap_getword_nulls(r->pool, &pair, '!'));
  //APACHE_TABLE_ADD(cookie, "sigtype", ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(cookie, "key", ap_getword_nulls(r->pool, &pair, '!')); 
  //APACHE_TABLE_ADD(cookie, "dflt_key", ap_getword_nulls(r->pool, &pair, '!'));
  APACHE_TABLE_ADD(cookie, "sig", ap_getword_nulls(r->pool, &pair, '!'));

  return cookie;

}

/* --- */

static char *
get_cookie_str(request_rec *r, 
	       char *cookie_name) 

{

  const char *data = APACHE_TABLE_GET(r->headers_in, "Cookie");

  const char *pair;

  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		   "get_cookie_str...");

  if (!data) return NULL;

  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		   "cookie data = %s", data);

  while (*data && (pair = ap_getword(r->pool, &data, ';'))) {
    const char *name;
    if (*data == ' ') ++data;
    name = ap_getword(r->pool, &pair, '=');

    APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		     "current cookie name = %s", name);
    APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		     "current cookie data = %s", pair);

    if (strcmp(name, cookie_name) == 0) {
      APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		       "found cookie match!");
      return (char *)pair;
    }
  }
  return NULL;

}

/* --- */

static char *
cookie_check_sig_string(request_rec *r, 
			APACHE_TABLE *cookie) 

{

  return APACHE_PSTRCAT
    (r->pool,
     APACHE_TABLE_GET(cookie, "ver"), "!",
     APACHE_TABLE_GET(cookie, "status"), "!",
     APACHE_TABLE_GET(cookie, "msg"), "!",
     APACHE_TABLE_GET(cookie, "issue"), "!",
     APACHE_TABLE_GET(cookie, "expire"), "!",
     APACHE_TABLE_GET(cookie, "id"), "!",
     APACHE_TABLE_GET(cookie, "principal"), "!",
     APACHE_TABLE_GET(cookie, "auth"), "!",
     APACHE_TABLE_GET(cookie, "sso"), "!",
     APACHE_TABLE_GET(cookie, "params"), NULL);
  
}

/* --- */

static char *
wls_response_check_sig_string(request_rec *r, 
			      APACHE_TABLE *wls_response) {

  return APACHE_PSTRCAT
    (r->pool,
     APACHE_TABLE_GET(wls_response, "ver"), "!",
     APACHE_TABLE_GET(wls_response, "status"), "!",
     APACHE_TABLE_GET(wls_response, "msg"), "!",
     APACHE_TABLE_GET(wls_response, "issue"), "!",
     APACHE_TABLE_GET(wls_response, "id"), "!",
     APACHE_TABLE_GET(wls_response, "url"), "!",
     APACHE_TABLE_GET(wls_response, "principal"), "!",
     APACHE_TABLE_GET(wls_response, "auth"), "!",
     APACHE_TABLE_GET(wls_response, "sso"), "!",
     APACHE_TABLE_GET(wls_response, "life"), "!",
     APACHE_TABLE_GET(wls_response, "params"), NULL);

}

/* --- */
/* modified base64 encoding */

static char *
wls_encode(request_rec *r, 
	   char *string) 

{

  char *result = APACHE_BASE64_ENCODE(r->pool, string);
  int i;
  
  for (i = 0; i < strlen(result); i++) {
    if (result[i] == '+') result[i] = '-';
    else if (result[i] == '/') result[i] = '.';
    else if (result[i] == '=') result[i] = '_';
  }
  
  return result;

}

/* --- */
/* modified base64 decoding */

static char *
wls_decode(request_rec *r, 
	   char *string) 

{

  char *result = APACHE_PSTRDUP(r->pool, string);
  int i;

  for (i = 0; i < strlen(result); i++) {
    if (result[i] == '-') result[i] = '+';
    else if (result[i] == '.') result[i] = '/';
    else if (result[i] == '_') result[i] = '=';
  }

  return (char *)APACHE_BASE64_DECODE(r->pool, result);

}

/* --- */
/* ISO 2 datetime encoding */

static char *
iso2_time_encode(request_rec *r, 
		 APACHE_TIME t) 

{
  
  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		   "ISO 2 time encoding...");
  return ap_ht_time(r->pool, t, "%Y%m%dT%H%M%SZ", 1);

}

/* --- */
/* ISO 2 datetime decoding */

static APACHE_TIME 
iso2_time_decode(request_rec *r, 
				    char *t_iso2) 

{
  
  char *t_http = (char*)APACHE_PALLOC(r->pool, 27);

  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		   "iso2_time_decode...");

  if (strlen(t_iso2) < 16) return -1;
  t_http[0] = ',';
  t_http[1] = ' ';
  // day
  t_http[2] = t_iso2[6];
  t_http[3] = t_iso2[7];
  t_http[4] = ' ';
  // month
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
  // year
  t_http[9] = t_iso2[0];
  t_http[10] = t_iso2[1];
  t_http[11] = t_iso2[2];
  t_http[12] = t_iso2[3];
  t_http[13] = ' ';
  // time
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

  APACHE_LOG_ERROR(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, r,
		   "HTTP date = %s", t_http);
  
  return APACHE_PARSE_HTTP_DATE(t_http);

}


/* --- */

static int 
using_https(request_rec *r) 

{

  return (APACHE_FNMATCH("https*", 
			 ap_construct_url(r->pool, r->unparsed_uri, r), 
			 0) != FNM_NOMATCH);

}

/* --- */

static char *
full_cookie_name(request_rec *r, 
		 char *cookie_name) 

{

  if (using_https(r)) {
    return APACHE_PSTRCAT(r->pool, cookie_name, "-S", NULL);
  }
  return (char *)APACHE_PSTRDUP(r->pool, cookie_name);

}

/* --- */

static char *
get_url(request_rec *r) 

{

  /* NO!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

  if (using_https(r)) { 
    return APACHE_PSTRCAT
      (r->pool,
       "https://", APACHE_TABLE_GET(r->headers_in, "Host"), r->parsed_uri.path,
       NULL);
  } else {
    return APACHE_PSTRCAT
      (r->pool,
       "http://", APACHE_TABLE_GET(r->headers_in, "Host"), r->parsed_uri.path,
       NULL);
  }

  */

  /* This is rumored not to work, perhaps in Apache 2, perhaps
     depending on the presence (or otherwise) of ServerName and/or
     Port and/or Listen directive. Needs testing. Also needs testing
     to ensure it *NEVER* uses hostname from a Host: header or from a
     full URL on the request line , and that it gets port numbers
     right. Otherwise it should be fine :-) */ 

  return ap_construct_url(r->pool, r->uri, r);

}

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
  return "Unreconised error code";

}

/* --- */

static char *
no_cookie(request_rec *r, 
	  mod_ucam_webauth_cfg *c) 

{

  char *cookie_name = 
    ap_escape_html(r->pool, full_cookie_name(r, c->AACookieName));
  char *cookie_domain;
  char *host = ap_escape_html(r->pool, ap_get_server_name(r));
  char *port = APACHE_PSPRINTF(r->pool, "%d", ap_get_server_port(r));
  if (c->AACookieDomain != NULL) {
    cookie_domain = APACHE_PSTRCAT(r->pool,
				  "computers in the domain <tt>",
				  ap_escape_html(r->pool, c->AACookieDomain),
				  "</tt>", NULL);
  } else {
    cookie_domain = "this web server";
  }

  return APACHE_PSTRCAT
    (r->pool,
     "<html><head><title>Error - missing cookie</title></head>"
     "<body><h1>Error - missing cookie</h1>"
     "<p>The web resource you are trying to access is protected "
     "by a system that uses a browser cookie to track your "
     "authentication state. Your browser does not seem to be "
     "returning an appropriate cookie, probably because it has "
     "been configured to reject some or all cookies. To access "
     "this resource you must at least accept a cookie called "
     "'<tt><b>", cookie_name, "</b></tt>' from ", cookie_domain,
     ".</p><p>This cookie will be deleted when you quit your "
     "web browser. It contains your identity and other information "
     "used to manage authentication.</p><hr><i>mod_ucam_webauth "
     "running on ", host, " Port ", port, "</i></body></hmtl>", NULL);

}


/* --- */

static char *
auth_cancelled(request_rec *r) 

{

  char *host = ap_escape_html(r->pool, ap_get_server_name(r));
  char *port = APACHE_PSPRINTF(r->pool, "%d", ap_get_server_port(r));
  char *admin = ap_escape_html(r->pool, r->server->server_admin);
  if (admin != NULL) {
    admin = APACHE_PSTRCAT(r->pool, "(<tt><b>", admin, "</b></tt>)", NULL);
  } else {
    admin = "";
  }

  return APACHE_PSTRCAT
    (r->pool,
     "<html><head><title>Error - authentication cancelled</title></head>"
     "<body><h1>Error - authentication cancelled</h1>"
     "<p>Authentication has been cancelled at your request. Unfortunately "
     "this means you will not be able to access the resource that you "
     "requested</p>"
     "<p>If you cancelled authentication because you do not have a "
     "suitable username and password then you should contact the "
     "authentication system administrator to see if you can be "
     "registered. If you cancelled because of privacy concerns then you "
     "should contact the administrator of this server ", admin, " to see "
     "if there are other ways for you to access this resource.</p>"
     "<hr><i>mod_ucam_webauth running on ", host, " Port ", port,
     "</i></body></html>", NULL);

}

/* --- */

static char *
auth_required(request_rec *r) 

{

  char *host = ap_escape_html(r->pool, ap_get_server_name(r));
  char *port = APACHE_PSPRINTF(r->pool, "%d", ap_get_server_port(r));
  char *admin = ap_escape_html(r->pool, r->server->server_admin);
  char *user = ap_escape_html(r->pool, APACHE_REQUEST_USER);
  if (admin != NULL) {
    admin = APACHE_PSTRCAT(r->pool, "(<tt><b>", admin, "</b></tt>)", NULL);
  } else {
    admin = "";
  }
  if (user != NULL) {
    user = APACHE_PSTRCAT(r->pool, "(<tt><b>", user, "</b></tt>)", NULL);
  } else {
    user = "";
  }

  return APACHE_PSTRCAT
    (r->pool,
     "<html><head><title>Error - authorization required</title></head>"
     "<body><h1>Error - authorization required</h1>"
     "<p>Access to the web resource you are trying to obtain is "
     "restricted. The identity that you have established ", user,
     " does not appear to be allowed access. Please contact the "
     "administrator of this server ", admin, " for further details.</p>"
     "<hr><i>mod_ucam_webauth running on ", host, " Port ", port,
     "</i>\n\n"
     "<!-- This is padding to convince STUPID INTERNET EXPLORER that"
     "     I do know what I'm doing and that this error message"
     "     contains useful information. Without the padding, IE"
     "     will by default 'helpfully' display a useless error page"
     "     in place of my carefully crafted words. Bah! (Jon)"
     "--></body></html>", NULL);

}


/* ---------------------------------------------------------------------- */

/* make Apache aware of Raven authentication handler */

#if defined APACHE_RELEASE && APACHE_RELEASE < 20000000

module MODULE_VAR_EXPORT ucam_webauth_module = {
  STANDARD_MODULE_STUFF,
  NULL,
  create_dir_config,
  NULL,
  create_server_config,
  NULL,
  config_commands,
  NULL,
  NULL,
  ucam_webauth_handler,
  /*ucam_webauth_authz,*/ NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL
};

#else

static void register_hooks(apr_pool_t *p) {
  ap_hook_check_user_id(ucam_webauth_handler, NULL, NULL, APR_HOOK_FIRST);
  //ap_hook_auth_checker(ucam_webauth_authz, NULL, NULL, HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA ucam_webauth_module = {
  STANDARD20_MODULE_STUFF,
  create_dir_config,    /* create per-directory config structures */
  NULL,                 /* merge per-directory config structures  */
  create_server_config, /* create per-server config structures    */
  NULL,                 /* merge per-server config structures     */
  config_commands,      /* command handlers */
  register_hooks        /* register hooks */
};

#endif


/* ---------------------------------------------------------------------- */

