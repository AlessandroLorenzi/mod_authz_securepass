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

#define AUTHZ_GRANTED 1
#define AUTHZ_DENIED 0

/*
 * Structure for the module itself.  The actual definition of this structure
 * is at the end of the file.
 */
module AP_MODULE_DECLARE_DATA authz_securepass_module;

/*
 *  Data type for per-directory configuration
 */

typedef struct
{
    int  enabled;
    int  authoritative;

} authz_securepass_dir_config_rec;




static int check_securepass_realm(request_rec *r, const char *realmlist)
{
    // Al posto di questo fare il match del nome.
    char **p;
    char *user= r->user;
    char *realm,*w, *at;

    
    // estrapolo il realm dell'utente
    realm=strchr(user,'@');
    realm++;
	
    /* Loop through list of realms passed in */
    while (*realmlist != '\0')
    {
		// controlla la lista dei gruppi nella configurazione.
		w= ap_getword_conf(r->pool, &realmlist);
		// in w dovrebbe esserci il gruppo autorizzato
		// devo vedere se realm e w sono uguali
		
		/* Debug log */
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
    	                  "SecurePass: checking realm %s", w);

		/* Walk through list of members, seeing if any match user login */
		if (strcmp(realm,w)==0)
		{
			return 1;
		}
    }

    /* Didn't find any matches, flunk him */
    if (at != NULL) *at= '@';
    return 0;
}


/*
 * Creator for per-dir configurations.  This is called via the hook in the
 * module declaration to allocate and initialize the per-directory
 * configuration data structures declared above.
 */

static void *create_authz_securepass_dir_config(apr_pool_t *p, char *d)
{
    authz_securepass_dir_config_rec *dir= (authz_securepass_dir_config_rec *)
	apr_palloc(p, sizeof(authz_securepass_dir_config_rec));

    dir->enabled= 0;
    dir->authoritative= 1;	/* strong by default */

    return dir;
}


/*
 * Config file commands that this module can handle
 */

static const command_rec authz_securepass_cmds[] =
{
    AP_INIT_FLAG("AuthzSecurepass",
	ap_set_flag_slot,
	(void *)APR_OFFSETOF(authz_securepass_dir_config_rec, enabled),
	OR_AUTHCFG,
	"Set to 'on' to enable SecurePass module"),

    AP_INIT_FLAG("AuthzSecurepassAuthoritative",
	ap_set_flag_slot,
	(void *)APR_OFFSETOF(authz_securepass_dir_config_rec, authoritative),
	OR_AUTHCFG,
	"Set to 'off' to allow access control to be passed along to lower "
	    "modules if this module can't confirm access rights" ),

    { NULL }
};


/* Check if the named user is in the given list of groups.  The list of
 * groups is a string with groups separated by white space.  Group ids
 * can either be unix group names or numeric group id numbers.  There must
 * be a unix login corresponding to the named user.
 */

static int check_unix_group(request_rec *r, const char *grouplist)
{
	return 0;
}


static int authz_securepass_check_user_access(request_rec *r) 
{
    authz_securepass_dir_config_rec *dir= (authz_securepass_dir_config_rec *)
	ap_get_module_config(r->per_dir_config, &authz_securepass_module);

    int m= r->method_number;
    int required_group= 0;
    register int x;
    const char *t, *w;
    const apr_array_header_t *reqs_arr= ap_requires(r);
    const char *filegroup= NULL;
    require_line *reqs;


    /* If not enabled, pass */
    if ( !dir->enabled ) return DECLINED;

    /* If there are no Require arguments, pass */
    if (!reqs_arr) return DECLINED;
    reqs=  (require_line *)reqs_arr->elts;

    /* Loop through the "Require" argument list */
    for(x= 0; x < reqs_arr->nelts; x++)
    {
	if (!(reqs[x].method_mask & (AP_METHOD_BIT << m))) continue;

	t= reqs[x].requirement;
	w= ap_getword_white(r->pool, &t);

        /* Check if we have a realm
         * and match the user
         */

	if ( !strcasecmp(w, "sprealm"))
	{
	  if (check_securepass_realm(r,t)){

	     /* Debug message, check_securepass_realm succeeded */
             ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
    	                  "SecurePass user %s in realm list", r->user);

	     /* Return authorized */
             return OK;
          }
	  else {
	     /* If we have debug active, print out that is not in list */
             ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
    	                  "SecurePass user %s not in realm list", r->user);
          }

	}
    
	if ( !strcasecmp(w, "spgroup"))
	{
	  /* dummy, check securepass group */
	}

	/* The 'file-group' directive causes mod_authz_owner to store the
	 * group name of the file we are trying to access in a note attached
	 * to the request.  It's our job to decide if the user actually is
	 * in that group.  If the note is missing, we just ignore it.
	 * Probably mod_authz_owner is not installed.
	 */
	if ( !strcasecmp(w, "file-group"))
	{
	    filegroup= apr_table_get(r->notes, AUTHZ_GROUP_NOTE);
	    if (filegroup == NULL) continue;
	}

	if ( !strcmp(w,"group") || filegroup != NULL)
	{
	    required_group= 1;

	    if (filegroup)
	    {
		/* Check if user is in the group that owns the file */
		if (check_unix_group(r,filegroup))
		    return OK;
	    }
	    else if (t[0])
	    {
		/* Pass rest of require line to authenticator */
		if (check_unix_group(r,t))
		    return OK;
	    }
	}
    }
    
    /* If we didn't see a 'require group' or aren't authoritive, decline */
    if (!required_group || !dir->authoritative)
	return DECLINED;

    /* Authentication failed and we are authoritive, declare unauthorized */
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
    	"access to %s failed, reason: user %s not allowed access",
    	r->uri, r->user);

    ap_note_basic_auth_failure(r);
    return HTTP_UNAUTHORIZED;
}

static void authz_securepass_register_hooks(apr_pool_t *p)
{
    ap_hook_auth_checker(authz_securepass_check_user_access, NULL, NULL,
	    APR_HOOK_MIDDLE);
}
    

module AP_MODULE_DECLARE_DATA authz_securepass_module = {
    STANDARD20_MODULE_STUFF,
    create_authz_securepass_dir_config,	  /* create per-dir config */
    NULL,			          /* merge per-dir config */
    NULL,			          /* create per-server config */
    NULL,			          /* merge per-server config */
    authz_securepass_cmds,	          /* command apr_table_t */
    authz_securepass_register_hooks        /* register hooks */
};





