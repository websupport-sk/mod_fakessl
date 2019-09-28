/*
 * instalation: /usr/apache/bin/apxs -a -i -c mod_fakessl.c
 */

#include "apr_strings.h"
#include "apr_md5.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "mpm_common.h"

#define MODULE			"mod_fakessl"

module AP_MODULE_DECLARE_DATA fakessl_module;
APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));

static int fakessl_stuff(request_rec *r)
{
	apr_table_t *env = r->subprocess_env;

	if (apr_table_get(r->headers_in, "X-Forwarded-Proto") && !strcmp("https", apr_table_get(r->headers_in, "X-Forwarded-Proto"))) {
		apr_table_setn(env, "HTTPS", "on");
		apr_table_set(r->connection->notes, "fakessl_https", "on");
	} else {
		apr_table_unset(r->connection->notes, "fakessl_https");
	}

	return DECLINED;
}

static const char *fakessl_hook_http_scheme(const request_rec *r)
{
	if (apr_table_get(r->headers_in, "X-Forwarded-Proto") && !strcmp("https", apr_table_get(r->headers_in, "X-Forwarded-Proto"))) {
		return "https";
	}

	return "http";
}

static apr_port_t fakessl_hook_default_port(const request_rec *r)
{                                
	if (apr_table_get(r->headers_in, "X-Forwarded-Proto") && !strcmp("https", apr_table_get(r->headers_in, "X-Forwarded-Proto"))) {
		return 443;
	}
	return 0;  
}

static int ssl_is_https(conn_rec *c) {
    return apr_table_get(c->notes, "fakessl_https") != NULL;
}

static void register_hooks (apr_pool_t * p)
{
	ap_hook_post_read_request(fakessl_stuff, NULL, NULL, APR_HOOK_FIRST);
	ap_hook_http_scheme (fakessl_hook_http_scheme,   NULL,NULL, APR_HOOK_FIRST);
	ap_hook_default_port  (fakessl_hook_default_port,  NULL,NULL, APR_HOOK_FIRST);

    /* this will only work if mod_ssl is not loaded */
    if (APR_RETRIEVE_OPTIONAL_FN(ssl_is_https) == NULL)
        APR_REGISTER_OPTIONAL_FN(ssl_is_https);
}

module AP_MODULE_DECLARE_DATA fakessl_module = {
	STANDARD20_MODULE_STUFF,
	NULL,				/* dir config creater */
	NULL,				/* dir merger --- default is to override */
	NULL,			/* server config */
	NULL,				/* merge server config */
	NULL,			/* command apr_table_t */
	register_hooks			/* register hooks */
};
