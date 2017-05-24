/*

   This file is part of the University of Cambridge Web Authentication
   System Application Agent for Apache 1.3 and 2
   See http://raven.cam.ac.uk/ for more details

   Copyright (c) University of Cambridge 2005

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

   Author: Jon Warbrick <jw35@cam.ac.uk>

*/

#define VERSION "0.0.1"

#include <string.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"

#if defined APACHE_RELEASE && APACHE_RELEASE < 20000000
#define APACHE1_3
#endif

/* logging macro. Note that it will only work in an environment where
   'r' holds a copy of the current request record */

#ifdef APACHE1_3
#define APACHE_LOG0(level, fmt) \
  ap_log_rerror(APLOG_MARK, level | APLOG_NOERRNO, r, fmt)
#define APACHE_LOG1(level, fmt, a) \
  ap_log_rerror(APLOG_MARK, level | APLOG_NOERRNO, r, fmt, a)
#define APACHE_LOG2(level, fmt, a, b) \
  ap_log_rerror(APLOG_MARK, level | APLOG_NOERRNO, r, fmt, a, b)
#else
#define APACHE_LOG0(level, fmt) \
  ap_log_rerror(APLOG_MARK, level, 0, r, fmt)
#define APACHE_LOG1(level, fmt, a) \
  ap_log_rerror(APLOG_MARK, level, 0, r, fmt, a)
#define APACHE_LOG2(level, fmt, a, b) \
  ap_log_rerror(APLOG_MARK, level, 0, r, fmt, a, b)
#endif

/* Almost all of the code is written as for Apache 2. The folowing
   macros adapt it for Apache 1.3 if necessary */

#ifdef APACHE1_3
#define AP_MODULE_DECLARE_DATA MODULE_VAR_EXPORT
#endif

/* ---------------------------------------------------------------------- */

/* Standard forward declaration of the module structure since
   _something_ is bound to need it before it's defined at the end */

module AP_MODULE_DECLARE_DATA ucam_none_module;

/* Auth handler */

static int
none_authn(request_rec *r)

{

  const char *t;

  if (!(t = ap_auth_type(r)) || strcasecmp(t, "None")) {
    APACHE_LOG2
      (APLOG_DEBUG,"mod_ucam_none declining authn for %s (AuthType = %s)",
       r->uri, ap_auth_type(r) == NULL ? "(null)" : ap_auth_type(r));
    return DECLINED;
  }

  APACHE_LOG1(APLOG_DEBUG,"mod_ucam_none accepting authn for %s ", r->uri);

#ifdef APACHE1_3
  r->connection->user = "nobody";
  r->connection->ap_auth_type = "None";
#else
  r->user = "nobody";
  r->ap_auth_type = "None";
#endif

  return OK;

}

/* ---------------------------------------------------------------------- */

/* make Apache aware of the handlers */

#ifdef APACHE1_3

module MODULE_VAR_EXPORT ucam_none_module = {
  STANDARD_MODULE_STUFF,
  NULL,                         /* initializer */
  NULL,                         /* dir config creator */
  NULL,                         /* dir merger --- default is to override */
  NULL,                         /* server config */
  NULL,                         /* merge server config */
  NULL,                         /* command table */
  NULL,                         /* handlers */
  NULL,                         /* filename translation */
  none_authn,                   /* check_user_id */
  NULL,                         /* check auth */
  NULL,                         /* check access */
  NULL,                         /* type_checker */
  NULL,                         /* fixups */
  NULL,                         /* logger */
  NULL,                         /* header parser */
  NULL,                         /* child_init */
  NULL,                         /* child_exit */
  NULL                          /* post read-request */
};

#else

static void none_register_hooks(apr_pool_t *p) {
  ap_hook_check_user_id
    (none_authn, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA ucam_none_module = {
  STANDARD20_MODULE_STUFF,
  NULL,                         /* create per-directory config structures */
  NULL,                         /* merge per-directory config structures  */
  NULL,                         /* create per-server config structures    */
  NULL,                         /* merge per-server config structures     */
  NULL,                         /* command handlers */
  none_register_hooks           /* register hooks */
};

#endif

/* ---------------------------------------------------------------------- */



