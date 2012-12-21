/*
 * Modifica di mod_authz_unixrealm.c per controllare il permesso
 * con i gruppi di securepass
 * Author: Alessandro Lorenzi <alessandro.lorenzi@garl.ch>
 *
 * */

#include "apr_lib.h"

#include "ap_config.h"
#include "ap_provider.h"
#include "mod_auth.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"	/* for ap_hook_(check_user_id | auth_checker)*/
#if HAVE_PWD_H
#include <pwd.h>
#endif
#if HAVE_GRP_H
#include <grp.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/*
 * Structure for the module itself.  The actual definition of this structure
 * is at the end of the file.
 */
module AP_MODULE_DECLARE_DATA authz_securepassrealm_module;

/* A handle for retrieving the requested file's realm from mod_authnz_owner */
APR_DECLARE_OPTIONAL_FN(char*, authz_owner_get_file_realm, (request_rec *r));


/* Check if the named user is in the given list of realms.  The list of
 * realms is a string with realms separated by white space.  realm ids
 * can either be unix realm names or numeric realm id numbers.  There must
 * be a unix login corresponding to the named user.
 */

static int check_securepass_realm(request_rec *r, const char *realmlist)
{
    // Al posto di questo fare il match del nome.
    char **p;
    char *user= r->user;
    char *realm,*w, *at;

	// estrapolo il realm dell'utente
	realm=strchr(str,'@');
	realm++;
	
    /* Loop through list of realms passed in */
    while (*realmlist != '\0')
    {
		// controlla la lista dei gruppi nella configurazione.
		w= ap_getword_conf(r->pool, &realmlist);
		// in w dovrebbe esserci il gruppo autorizzato
		// devo vedere se realm e w sono uguali

		/* Walk through list of members, seeing if any match user login */
		if (realm.compare(w)==0)
		{
			return 1;
		}
    }

    /* Didn't find any matches, flunk him */
    if (at != NULL) *at= '@';
    return 0;
}



static authz_status securepassrealm_check_authorization(request_rec *r,
        const char *require_args, const void *parsed_require_args)
{
    /* If no authenticated user, pass */
    if ( !r->user ) return AUTHZ_DENIED_NO_USER;

    if (check_securepass_realm(r,require_args))
	return AUTHZ_GRANTED;

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
        "Authorization of user %s to access %s failed. "
        "User not in Required securepass realms (%s).",
        r->user, r->uri, require_args);

    return AUTHZ_DENIED;
}


/*   da qui in poi dovrebbe riguardare i file, quindi... ¿¿??  */

APR_OPTIONAL_FN_TYPE(authz_ownsecurepasser_get_file_realm) *authz_owner_get_file_realm;

static authz_status securepassfilerealm_check_authorization(request_rec *r,
        const char *require_args, const void *parsed_require_args)
{
    const char *filerealm= NULL;

    /* If no authenticated user, pass */
    if ( !r->user ) return AUTHZ_DENIED_NO_USER;

    /* Get realm name for requested file from mod_authz_owner */
    filerealm= authz_owner_get_file_realm(r);

    if (!filerealm)
        /* No errog log entry, because mod_authz_owner already made one */
        return AUTHZ_DENIED;

    if (check_securepass_realm(r,filerealm))
	return AUTHZ_GRANTED;
    
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
        "Authorization of user %s to access %s failed. "
        "User not in Required securepass file realm (%s).",
        r->user, r->uri, filerealm);

    return AUTHZ_DENIED;
}

static const authz_provider authz_securepassrealm_provider =
{
    &securepassrealm_check_authorization,
    NULL,
};

static const authz_provider authz_securepassfilerealm_provider =
{
    &securepassfilerealm_check_authorization,
    NULL,
};

static void authz_securepassrealm_register_hooks(apr_pool_t *p)
{
    /* Get a handle on mod_authz_owner */
    authz_owner_get_file_realm = APR_RETRIEVE_OPTIONAL_FN(authz_owner_get_file_realm);

    /* Register authz providers */
    ap_register_auth_provider(p, AUTHZ_PROVIDER_REALM, "securepass-realm",
            AUTHZ_PROVIDER_VERSION,
            &authz_securepassrealm_provider, AP_AUTH_INTERNAL_PER_CONF);

    ap_register_auth_provider(p, AUTHZ_PROVIDER_REALM, "securepass-file-realm",
            AUTHZ_PROVIDER_VERSION,
            &authz_securepassfilerealm_provider, AP_AUTH_INTERNAL_PER_CONF);
}
    
module AP_MODULE_DECLARE_DATA authz_securepassrealm_module = {
    STANDARD20_MODULE_STUFF,
    NULL,				  /* create per-dir config */
    NULL,			          /* merge per-dir config */
    NULL,			          /* create per-server config */
    NULL,			          /* merge per-server config */
    NULL,		         	  /* command apr_table_t */
    authz_securepassrealm_register_hooks        /* register hooks */
};
