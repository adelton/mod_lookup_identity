
#include <stdio.h>
#include "apr_hash.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "apr_strings.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include <pwd.h>
#include <grp.h>

static const int LOOKUP_IDENTITY_OUTPUT_NONE = 0;
static const int LOOKUP_IDENTITY_OUTPUT_NOTES = 1;
static const int LOOKUP_IDENTITY_OUTPUT_ENV = 2;
static const int LOOKUP_IDENTITY_OUTPUT_ALL = 3;
static const int LOOKUP_IDENTITY_OUTPUT_DEFAULT = 4;

static char * LOOKUP_IDENTITY_OUTPUT_GECOS = "REMOTE_USER_GECOS";
static char * LOOKUP_IDENTITY_OUTPUT_GROUPS = "REMOTE_USER_GROUPS";
static char * LOOKUP_IDENTITY_OUTPUT_GROUPS_SEP = ":";

typedef struct lookup_identity_config {
	char * context;
	int output;
	char * output_gecos;
	char * output_groups;
	char * output_groups_sep;
} lookup_identity_config;

module AP_MODULE_DECLARE_DATA lookup_identity_module;

static int lookup_identity_hook(request_rec * r) {
	lookup_identity_config * cfg = (lookup_identity_config *) ap_get_module_config(r->per_dir_config, &lookup_identity_module);
	lookup_identity_config * srv_cfg = (lookup_identity_config *) ap_get_module_config(r->server->module_config, &lookup_identity_module);
	if (! r->user) {
		return DECLINED;
	}
	if (!(cfg || srv_cfg)) {
		return DECLINED;
	}
	lookup_identity_config the_config;
	the_config.output = cfg && cfg->output != LOOKUP_IDENTITY_OUTPUT_DEFAULT
		? cfg->output
		: srv_cfg && srv_cfg->output != LOOKUP_IDENTITY_OUTPUT_DEFAULT
			? srv_cfg->output
			: LOOKUP_IDENTITY_OUTPUT_ALL;
	if (!(the_config.output & LOOKUP_IDENTITY_OUTPUT_ALL)) {
		return DECLINED;
	}

	the_config.output_gecos = cfg && cfg->output_gecos ? cfg->output_gecos
		: srv_cfg && srv_cfg->output_gecos ? srv_cfg->output_gecos : LOOKUP_IDENTITY_OUTPUT_GECOS;
	the_config.output_groups = cfg && cfg->output_groups ? cfg->output_groups
		: srv_cfg && srv_cfg->output_groups ? srv_cfg->output_groups : LOOKUP_IDENTITY_OUTPUT_GROUPS;
	the_config.output_groups_sep = cfg && cfg->output_groups_sep ? cfg->output_groups_sep
		: srv_cfg && srv_cfg->output_groups_sep ? srv_cfg->output_groups_sep : LOOKUP_IDENTITY_OUTPUT_GROUPS_SEP;
	
	struct passwd * pwd = getpwnam(r->user);
	if (! pwd) {
		return DECLINED;
	}
	int ngroups = 3;
	gid_t * groups;
	groups = malloc(sizeof(gid_t) * ngroups);
	if (! groups) {
		return DECLINED;
	}
	while (getgrouplist(r->user, pwd->pw_gid, groups, &ngroups) == -1) {
		free(groups);
		groups = malloc(sizeof(gid_t) * ngroups);
		if (! groups) {
			return DECLINED;
		}
	}
	int i, len;
	len = 0;
	struct group * gr;
	for (i = 0; i < ngroups; i++) {
		if (len)
			len += strlen(the_config.output_groups_sep);
		gr = getgrgid(groups[i]);
		if (gr)
			len += strlen(gr->gr_name);
	}
	if (len) {
		char * buffer = apr_palloc(r->pool, len + 1);
		len = 0;
		for (i = 0; i < ngroups; i++) {
			gr = getgrgid(groups[i]);
			if (gr) {
				if (len) {
					strcpy(buffer + len, the_config.output_groups_sep);
					len += strlen(the_config.output_groups_sep);
				}
				strcpy(buffer + len, gr->gr_name);
				len += strlen(gr->gr_name);
			}
		}
		buffer[len] = '\0';
		if (the_config.output & LOOKUP_IDENTITY_OUTPUT_NOTES) {
			apr_table_setn(r->notes, the_config.output_groups, buffer);
		}
		if (the_config.output & LOOKUP_IDENTITY_OUTPUT_ENV) {
			apr_table_setn(r->subprocess_env, the_config.output_groups, buffer);
		}
	}
	free(groups);

	if (the_config.output & LOOKUP_IDENTITY_OUTPUT_NOTES) {
		apr_table_set(r->notes, the_config.output_gecos, pwd->pw_gecos);
	}
	if (the_config.output & LOOKUP_IDENTITY_OUTPUT_ENV) {
		apr_table_set(r->subprocess_env, the_config.output_gecos, pwd->pw_gecos);
	}

	return OK;
}

const char * set_output(cmd_parms * cmd, void * conf_void, const char * arg) {
	lookup_identity_config * cfg = (lookup_identity_config *) conf_void;
	if (cfg) {
		if (!strcasecmp(arg, "none")) {
			cfg->output = LOOKUP_IDENTITY_OUTPUT_NONE;
		} else if (!strcasecmp(arg, "all")) {
			cfg->output = LOOKUP_IDENTITY_OUTPUT_ALL;
		} else if (!strcasecmp(arg, "env")) {
			cfg->output = LOOKUP_IDENTITY_OUTPUT_ENV;
		} else if (!strcasecmp(arg, "notes")) {
			cfg->output = LOOKUP_IDENTITY_OUTPUT_NOTES;
		}
	}
	return NULL;
}

const char * set_output_gecos(cmd_parms * cmd, void * conf_void, const char * arg) {
	lookup_identity_config * cfg = (lookup_identity_config *) conf_void;
	if (cfg) {
		if (!strcmp(arg, "default")) {
			cfg->output_gecos = LOOKUP_IDENTITY_OUTPUT_GECOS;
		} else {
			cfg->output_gecos = apr_pstrdup(cmd->pool, arg);
		}
	}
	return NULL;
}

const char * set_output_groups(cmd_parms * cmd, void * conf_void, const char * arg) {
	lookup_identity_config * cfg = (lookup_identity_config *) conf_void;
	if (cfg) {
		if (!strcmp(arg, "default")) {
			cfg->output_groups = LOOKUP_IDENTITY_OUTPUT_GROUPS;
		} else {
			cfg->output_groups = apr_pstrdup(cmd->pool, arg);
		}
	}
	return NULL;
}

const char * set_output_groups_separator(cmd_parms * cmd, void * conf_void, const char * arg) {
	lookup_identity_config * cfg = (lookup_identity_config *) conf_void;
	if (cfg) {
		if (!strcmp(arg, "default")) {
			cfg->output_groups_sep = LOOKUP_IDENTITY_OUTPUT_GROUPS_SEP;
		} else {
			cfg->output_groups_sep = apr_pstrdup(cmd->pool, arg);
		}
	}
	return NULL;
}

lookup_identity_config * create_common_conf(apr_pool_t * pool) {
	lookup_identity_config * cfg = apr_pcalloc(pool, sizeof(lookup_identity_config));
	if (cfg) {
		cfg->output = LOOKUP_IDENTITY_OUTPUT_DEFAULT;
	}
	return cfg;
}

void * create_server_conf(apr_pool_t * pool, server_rec * s) {
	lookup_identity_config * cfg = create_common_conf(pool);
	if (cfg)
		cfg->context = apr_psprintf(pool, "(server %s)", s->server_hostname);
	return cfg;
}

void * create_dir_conf(apr_pool_t * pool, char * context) {
	lookup_identity_config * cfg = create_common_conf(pool);
	if (cfg) {
		context = context ? context : "(no directory context)";
		cfg->context = apr_pstrdup(pool, context);
	}
	return cfg;
}

void * merge_dir_conf(apr_pool_t * pool, void * base_void, void * add_void) {
	lookup_identity_config * base = (lookup_identity_config *) base_void;
	lookup_identity_config * add = (lookup_identity_config *) add_void;
	lookup_identity_config * cfg = (lookup_identity_config *) create_dir_conf(pool, add->context);
	cfg->output = (add->output == LOOKUP_IDENTITY_OUTPUT_DEFAULT) ? base->output : add->output;
	cfg->output_gecos = add->output_gecos ? add->output_gecos : base->output_gecos;
	cfg->output_groups = add->output_groups ? add->output_groups : base->output_groups;
	cfg->output_groups_sep = add->output_groups_sep ? add->output_groups_sep : base->output_groups_sep;
	return cfg;
}

static const command_rec directives[] = {
	AP_INIT_TAKE1("LookupOutput", set_output, NULL, RSRC_CONF | ACCESS_CONF, "Specify where the lookup results should be stored"),
	AP_INIT_TAKE1("LookupOutputGECOS", set_output_gecos, NULL, RSRC_CONF | ACCESS_CONF, "Name of the note/variable for the GECOS information"),
	AP_INIT_TAKE1("LookupOutputGroups", set_output_groups, NULL, RSRC_CONF | ACCESS_CONF, "Name of the note/variable for the group information"),
	AP_INIT_TAKE1("LookupOutputGroupsSeparator", set_output_groups_separator, NULL, RSRC_CONF | ACCESS_CONF, "Group information separator"),
	{ NULL }
};

static void register_hooks(apr_pool_t * pool) {
	ap_hook_fixups(lookup_identity_hook, NULL, NULL, APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA lookup_identity_module = {
	STANDARD20_MODULE_STUFF,
	create_dir_conf,		/* Per-directory configuration handler */
	merge_dir_conf,			/* Merge handler for per-directory configurations */
	create_server_conf,		/* Per-server configuration handler */
	merge_dir_conf,			/* Merge handler for per-server configurations */
	directives,			/* Any directives we may have for httpd */
	register_hooks			/* Our hook registering function */
};

