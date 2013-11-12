
/*
 * Copyright 2013 Jan Pazdziora
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

#ifndef NO_USER_ATTR
#include <dbus/dbus.h>
#define DBUS_SSSD_PATH "/org/freedesktop/sssd/infopipe"
#define DBUS_SSSD_GET_USER_ATTR_IFACE "org.freedesktop.sssd.infopipe"
#define DBUS_SSSD_GET_USER_ATTR_METHOD "GetUserAttr"
#define DBUS_SSSD_GET_USER_ATTR_DEST "org.freedesktop.sssd.infopipe"
#define DBUS_SSSD_TIMEOUT 5000
#endif

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
#ifndef NO_USER_ATTR
	apr_hash_t * output_user_attr;
#endif
} lookup_identity_config;

module AP_MODULE_DECLARE_DATA lookup_identity_module;

static char * attr_array_concat(request_rec * r, DBusMessageIter *array_parent) {
        DBusMessageIter array_iter;
        int len = 0;
        const char *attr_sep = ":";
        char *buffer = NULL;
        const char *attrvalue;

        dbus_message_iter_recurse(array_parent, &array_iter);
        do {
                int type = dbus_message_iter_get_arg_type(&array_iter);
                if (type != DBUS_TYPE_STRING) {
                        continue;
                }

                if (len) {
                        len += strlen(attr_sep);
                }

                dbus_message_iter_get_basic(&array_iter, &attrvalue);
                len += strlen(attrvalue);
        } while (dbus_message_iter_next(&array_iter));

        if (len == 0) {
                return NULL;
        }

        buffer = apr_palloc(r->pool, len + 1);
        if (buffer == NULL) {
                return NULL;
        }
        len = 0;

        dbus_message_iter_recurse(array_parent, &array_iter);
        do {
                dbus_message_iter_get_basic(&array_iter, &attrvalue);

                if (len) {
                        strcpy(buffer + len, attr_sep);
                        len += strlen(attr_sep);
                }
                strcpy(buffer + len, attrvalue);
                len += strlen(attrvalue);
        } while (dbus_message_iter_next(&array_iter));

        buffer[len] = '\0';
        return buffer;
}

static int parse_getattr_reply(request_rec * r,
			    lookup_identity_config * the_config,
			    DBusMessage * reply) {
	DBusMessageIter iter;

	dbus_message_iter_init(reply, &iter);

	int type = dbus_message_iter_get_arg_type(&iter);
	if (type != DBUS_TYPE_ARRAY) {
                return DECLINED;
	}

	DBusMessageIter dict_iter;
	dbus_message_iter_recurse(&iter, &dict_iter);

        do {
                DBusMessageIter item_iter;
                DBusMessageIter value_iter;
                char *attrname;
                char *attrbuf;
                void *hash_value;

                type = dbus_message_iter_get_arg_type(&dict_iter);
                if (type != DBUS_TYPE_DICT_ENTRY) {
                        continue;
                }

                /* dicts are in fact tuples of two args - key and
                * value. Get the key first. That's just a string.
                */
                dbus_message_iter_recurse(&dict_iter, &item_iter);
                type = dbus_message_iter_get_arg_type(&item_iter);
                if (type != DBUS_TYPE_STRING) {
                        continue;
                }
                dbus_message_iter_get_basic(&item_iter, &attrname);

                /* Is this a key we requested? */
                hash_value = apr_hash_get(the_config->output_user_attr,
                        attrname, APR_HASH_KEY_STRING);
                if (hash_value == NULL) {
                        continue;
                }

                /* Value must be a variant */
                dbus_message_iter_next(&item_iter);
                type = dbus_message_iter_get_arg_type(&item_iter);
                if (type != DBUS_TYPE_VARIANT) {
                        continue;
                }

                /* Inside the variant is an array of strings with
                * values
                */
                dbus_message_iter_recurse(&item_iter, &value_iter);
                type = dbus_message_iter_get_arg_type(&value_iter);
                if (type != DBUS_TYPE_ARRAY) {
                        continue;
                }

                attrbuf = attr_array_concat(r, &value_iter);
                if (attrbuf == NULL) {
                        continue;
                }

                if (the_config->output & LOOKUP_IDENTITY_OUTPUT_NOTES) {
                        apr_table_set(r->notes, hash_value, attrbuf);
                }
                if (the_config->output & LOOKUP_IDENTITY_OUTPUT_ENV) {
                        apr_table_set(r->subprocess_env, hash_value, attrbuf);
                }
        } while (dbus_message_iter_next(&dict_iter));

	return OK;
}

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

#ifndef NO_USER_ATTR
	if (cfg && cfg->output_user_attr) {
		if (srv_cfg && srv_cfg->output_user_attr) {
			the_config.output_user_attr = apr_hash_overlay(r->pool, cfg->output_user_attr, srv_cfg->output_user_attr);
		} else {
			the_config.output_user_attr = cfg->output_user_attr;
		}
	} else if (srv_cfg && srv_cfg->output_user_attr) {
		the_config.output_user_attr = srv_cfg->output_user_attr;
	} else {
		the_config.output_user_attr = NULL;
	}

	if (the_config.output_user_attr) {
		DBusError error;
		dbus_error_init(&error);
		DBusConnection * connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
		if (! connection) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
				"Error connecting to system dbus: %s", error.message);
		} else {
			dbus_connection_set_exit_on_disconnect(connection, FALSE);
			const char * x_user = r->user;

                        DBusMessage * message = dbus_message_new_method_call(DBUS_SSSD_GET_USER_ATTR_DEST,
                                DBUS_SSSD_PATH,
                                DBUS_SSSD_GET_USER_ATTR_IFACE,
                                DBUS_SSSD_GET_USER_ATTR_METHOD);
                        if (! message) {
                                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Error allocating dbus message");
                                return DECLINED;
                        }
                        dbus_message_set_auto_start(message, TRUE);

                        dbus_bool_t dbret;
                        DBusMessageIter iter;
                        DBusMessageIter attr_array;
                        dbus_message_iter_init_append(message, &iter);
                        dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &x_user);

                        dbret = dbus_message_iter_open_container(&iter,
                                DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING,
                                &attr_array);
                        if (! dbret) {
                            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                                        "Could not open DBus container\n");
                            dbus_message_unref(message);
                            return DECLINED;
                        }

                        apr_hash_index_t * hi = apr_hash_first(r->pool, the_config.output_user_attr);
                        while (hi) {
                            const void * key;
                            void * value;

                            apr_hash_this(hi, &key, NULL, &value);
                            hi = apr_hash_next(hi);

                            dbret = dbus_message_iter_append_basic(&attr_array, DBUS_TYPE_STRING, &key);
                            if (! dbret) {
                                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                                            "Error appending key %s to dbus message",
                                            (const char *) key);
                                continue;
                            }
                        }

                        dbus_message_iter_close_container(&iter, &attr_array);
                        if (! dbret) {
                            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                                        "Could not close DBus container\n");
                            dbus_message_unref(message);
                            return DECLINED;
                        }

                        DBusMessage * reply = dbus_connection_send_with_reply_and_block(connection,
                                message, DBUS_SSSD_TIMEOUT, &error);
                        dbus_message_unref(message);
                        if (dbus_error_is_set(&error)) {
                                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                                        "Error calling %s(%s): %s: %s",
                                        DBUS_SSSD_GET_USER_ATTR_METHOD, x_user,
                                        error.name, error.message);
                                dbus_error_free(&error);
                                return DECLINED;
                        }

                        /* reply populated */
                        int reply_type = dbus_message_get_type(reply);

                        if (reply_type == DBUS_MESSAGE_TYPE_ERROR) {
                                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                                        "Error %s calling %s(%s)",
                                        dbus_message_get_error_name(reply),
                                        DBUS_SSSD_GET_USER_ATTR_METHOD, x_user);
                                dbus_message_unref(reply);
                                return DECLINED;
                        }
                        if (reply_type != DBUS_MESSAGE_TYPE_METHOD_RETURN) {
                                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                                        "Unexpected reply type %d calling %s(%s)", reply_type,
                                        DBUS_SSSD_GET_USER_ATTR_METHOD, x_user);
                                dbus_message_unref(reply);
                                return DECLINED;
                        }

                        int ret = parse_getattr_reply(r, &the_config, reply);
                        dbus_message_unref(reply);
                        if (ret != OK) {
                                ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                                        "Malformed reply in response to calling %s(%s)",
                                        DBUS_SSSD_GET_USER_ATTR_METHOD, x_user);
                                return DECLINED;
                        }
			dbus_connection_unref(connection);
		}
		dbus_error_free(&error);
	}
#endif

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

#ifndef NO_USER_ATTR
const char * set_user_attr(cmd_parms * cmd, void * conf_void, const char * attrib, const char * output) {
	lookup_identity_config * cfg = (lookup_identity_config *) conf_void;
	if (cfg) {
		if (!cfg->output_user_attr) {
			cfg->output_user_attr = apr_hash_make(cmd->pool);
		}
	        char * key = apr_pstrdup(cmd->pool, attrib);
	        char * value = apr_pstrdup(cmd->pool, output);
	        apr_hash_set(cfg->output_user_attr, key, APR_HASH_KEY_STRING, value);
	}
	return NULL;
}
#endif

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
#ifndef NO_USER_ATTR
	if (base->output_user_attr) {
		if (add->output_user_attr) {
			cfg->output_user_attr = apr_hash_overlay(pool, add->output_user_attr, base->output_user_attr);
		} else {
			cfg->output_user_attr = apr_hash_copy(pool, base->output_user_attr);
		}
	} else if (add->output_user_attr) {
		cfg->output_user_attr = apr_hash_copy(pool, add->output_user_attr);
	}
#endif
	return cfg;
}

static const command_rec directives[] = {
	AP_INIT_TAKE1("LookupOutput", set_output, NULL, RSRC_CONF | ACCESS_CONF, "Specify where the lookup results should be stored"),
	AP_INIT_TAKE1("LookupOutputGECOS", set_output_gecos, NULL, RSRC_CONF | ACCESS_CONF, "Name of the note/variable for the GECOS information"),
	AP_INIT_TAKE1("LookupOutputGroups", set_output_groups, NULL, RSRC_CONF | ACCESS_CONF, "Name of the note/variable for the group information"),
	AP_INIT_TAKE1("LookupOutputGroupsSeparator", set_output_groups_separator, NULL, RSRC_CONF | ACCESS_CONF, "Group information separator"),
#ifndef NO_USER_ATTR
	AP_INIT_TAKE2("LookupUserAttr", set_user_attr, NULL, RSRC_CONF | ACCESS_CONF, "Additional user attributes"),
#endif
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

