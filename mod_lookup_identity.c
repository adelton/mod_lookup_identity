
/*
 * Copyright 2013--2014 Jan Pazdziora
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
#include "apr_optional.h"
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
#define DBUS_SSSD_IFACE "org.freedesktop.sssd.infopipe"
#define DBUS_SSSD_GET_USER_GROUPS_METHOD "GetUserGroups"
#define DBUS_SSSD_GET_USER_ATTR_METHOD "GetUserAttr"
#define DBUS_SSSD_DEST "org.freedesktop.sssd.infopipe"
#define DBUS_SSSD_TIMEOUT 5000
#endif

static const int LOOKUP_IDENTITY_OUTPUT_NONE = 0;
static const int LOOKUP_IDENTITY_OUTPUT_NOTES = 1;
static const int LOOKUP_IDENTITY_OUTPUT_ENV = 2;
static const int LOOKUP_IDENTITY_OUTPUT_ALL = 3;
static const int LOOKUP_IDENTITY_OUTPUT_DEFAULT = 4;

static char * LOOKUP_IDENTITY_OUTPUT_GECOS = "REMOTE_USER_GECOS";

typedef struct lookup_identity_config {
	char * context;
	int output;
	char * output_gecos;
#ifndef NO_USER_ATTR
	char * output_groups;
	char * output_groups_sep;
	char * output_groups_iter;
	apr_hash_t * output_user_attr;
	apr_hash_t * output_user_attr_sep;
	apr_hash_t * output_user_attr_iter;
	int dbus_timeout;
#endif
} lookup_identity_config;

module AP_MODULE_DECLARE_DATA lookup_identity_module;

#ifndef NO_USER_ATTR
static DBusMessage * lookup_identity_dbus_message(request_rec * r, DBusConnection * connection, DBusError * error, int timeout, const char * method, apr_hash_t * hash) {
	DBusMessage * message = dbus_message_new_method_call(DBUS_SSSD_DEST,
		DBUS_SSSD_PATH,
		DBUS_SSSD_IFACE,
		method);
	if (! message) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Error allocating dbus message");
		return NULL;
	}
	dbus_message_set_auto_start(message, TRUE);

	char * user = r->user;
	int nargs = 0;
	const char ** args = NULL;
	if (hash && (nargs = apr_hash_count(hash))) {
		apr_hash_index_t * hi = apr_hash_first(r->pool, hash);
		args = apr_pcalloc(r->pool, nargs * sizeof(char *));
		for (int i = 0; hi; hi = apr_hash_next(hi), i++) {
			const void * ptr;
			apr_hash_this(hi, &ptr, NULL, NULL);
			args[i] = ptr;
		}
	}
	if (args) {
		dbus_message_append_args(message,
			DBUS_TYPE_STRING, &user,
			DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &args, nargs,
			DBUS_TYPE_INVALID);
	} else {
		dbus_message_append_args(message,
			DBUS_TYPE_STRING, &user,
			DBUS_TYPE_INVALID);
	}
	DBusMessage * reply = dbus_connection_send_with_reply_and_block(connection,
		message, timeout, error);
	dbus_message_unref(message);
	int is_error = 0;
	int reply_type = DBUS_MESSAGE_TYPE_ERROR;
	if (dbus_error_is_set(error)) {
		is_error = 1;
	} else {
		reply_type = dbus_message_get_type(reply);
		if (reply_type == DBUS_MESSAGE_TYPE_ERROR) {
			is_error = 1;
		} else if (reply_type != DBUS_MESSAGE_TYPE_METHOD_RETURN) {
			is_error = 1;
		}
	}
	if (is_error) {
		char * args_string = "";
		if (args) {
			int total_args_length = 0;
			int i;
			for (i = 0; i < nargs; i++) {
				total_args_length += strlen(args[i]) + 2;
			}
			args_string = apr_palloc(r->pool, total_args_length + 1);
			char * p = args_string;
			for (i = 0; i < nargs; i++) {
				strcpy(p, ", ");
				strcpy(p + 2, args[i]);
				p += strlen(args[i]) + 2;
			}
			args_string[total_args_length] = '\0';
		}
		if (dbus_error_is_set(error)) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
				"Error dbus calling %s(%s%s): %s: %s", method, user, args_string, error->name, error->message);
		} else if (reply_type == DBUS_MESSAGE_TYPE_ERROR) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
				"Error %s dbus calling %s(%s%s)", dbus_message_get_error_name(reply), method, user, args_string);
		} else {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
				"Error unexpected reply type %d dbus calling %s(%s%s)", reply_type, method, user, args_string);
		}
		if (reply) {
			dbus_message_unref(reply);
		}
		return NULL;
	}
	return reply;
}
#endif

static void lookup_identity_output_iter_to(request_rec * r, apr_table_t * t, const char * key, const apr_array_header_t * values) {
	int append = 0;
	if (key[0] == '+') {
		key++;
		append = 1;
	}
	long start = 0;
	const char * key_n = apr_pstrcat(r->pool, key, "_N", NULL);
	if (append) {
		const char * start_index = apr_table_get(t, key_n);
		if (start_index) {
			start = atol(start_index);
		}
	}
	for (int i = 0; values && i < values->nelts; i++) {
		apr_table_setn(t, apr_psprintf(r->pool, "%s_%ld", key, ++start), apr_pstrdup(r->pool, ((char **)values->elts)[i]));
	}
	apr_table_setn(t, key_n, apr_psprintf(r->pool, "%ld", start));
}
static void lookup_identity_output_iter(request_rec * r, int the_output, const char * key, const apr_array_header_t * values) {
	if (the_output & LOOKUP_IDENTITY_OUTPUT_NOTES) {
		lookup_identity_output_iter_to(r, r->notes, key, values);
	}
	if (the_output & LOOKUP_IDENTITY_OUTPUT_ENV) {
		lookup_identity_output_iter_to(r, r->subprocess_env, key, values);
	}
}

static void lookup_identity_output_data_to(request_rec * r, apr_table_t * t, const char * key, const apr_array_header_t * values, const char * sep) {
	int append = 0;
	if (key[0] == '+') {
		key++;
		append = 1;
	}
	const char * value = apr_table_get(t, key);
	char * out_value = NULL;
	if (value) {
		if (!(append && sep)) {
			return;
		}
		out_value = apr_pstrdup(r->pool, value);
	}
	for (int i = 0; values && i < values->nelts; i++) {
		if (!out_value) {
			out_value = apr_pstrdup(r->pool, ((char **)values->elts)[i]);
		} else {
			if (!sep) {
				break;
			}
			out_value = apr_pstrcat(r->pool, out_value, sep, NULL);
			out_value = apr_pstrcat(r->pool, out_value, ((char **)values->elts)[i], NULL);
		}
	}
	apr_table_setn(t, key, out_value);
}
static void lookup_identity_output_data(request_rec * r, int the_output, const char * key, const apr_array_header_t * values, const char * sep) {
	if (the_output & LOOKUP_IDENTITY_OUTPUT_NOTES) {
		lookup_identity_output_data_to(r, r->notes, key, values, sep);
	}
	if (the_output & LOOKUP_IDENTITY_OUTPUT_ENV) {
		lookup_identity_output_data_to(r, r->subprocess_env, key, values, sep);
	}
}

static void * merge_dir_conf(apr_pool_t * pool, void * base_void, void * add_void);
static lookup_identity_config * create_common_conf(apr_pool_t * pool);

static int lookup_identity_hook(request_rec * r) {
	lookup_identity_config * cfg = (lookup_identity_config *) ap_get_module_config(r->per_dir_config, &lookup_identity_module);
	lookup_identity_config * srv_cfg = (lookup_identity_config *) ap_get_module_config(r->server->module_config, &lookup_identity_module);
	if (! r->user) {
		return DECLINED;
	}
	if (!(cfg || srv_cfg)) {
		return DECLINED;
	}

	lookup_identity_config * the_config;
	if (srv_cfg) {
		if (cfg) {
			the_config = merge_dir_conf(r->pool, srv_cfg, cfg);
		} else {
			the_config = srv_cfg;
		}
	} else {
		the_config = cfg;
	}

	int the_output = the_config->output;
	if (the_output == LOOKUP_IDENTITY_OUTPUT_DEFAULT) {
		the_output = LOOKUP_IDENTITY_OUTPUT_ALL;
	} else if (!(the_output & LOOKUP_IDENTITY_OUTPUT_ALL)) {
		return DECLINED;
	}

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "invoked for user %s", r->user);

	struct passwd * pwd = getpwnam(r->user);
	if (! pwd) {
		return DECLINED;
	}

	if (the_config->output_gecos) {
		apr_array_header_t * gecos_array = apr_array_make(r->pool, 1, sizeof(char *));
		*(char **)apr_array_push(gecos_array) = pwd->pw_gecos;
		lookup_identity_output_data(r, the_output,
			the_config->output_gecos, gecos_array, NULL);
	}

#ifndef NO_USER_ATTR
	int the_timeout = DBUS_SSSD_TIMEOUT;
	if (the_config->dbus_timeout > 0) {
		the_timeout = the_config->dbus_timeout;
	}

	if (the_config->output_groups || the_config->output_groups_iter || the_config->output_user_attr) {
		DBusError error;
		dbus_error_init(&error);
		DBusConnection * connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
		if (! connection) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
				"Error connecting to system dbus: %s", error.message);
		} else {
			dbus_connection_set_exit_on_disconnect(connection, FALSE);
			if (the_config->output_groups || the_config->output_groups_iter) {
				DBusMessage * reply = lookup_identity_dbus_message(r, connection, &error, the_timeout, DBUS_SSSD_GET_USER_GROUPS_METHOD, NULL);
				int num;
				char ** ptr;
				if (reply && dbus_message_get_args(reply, &error, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &ptr, &num, DBUS_TYPE_INVALID)) {
					int i;
					apr_array_header_t * values = NULL;
					if (num) {
						values = apr_array_make(r->pool, num, sizeof(char *));
					}
					for (i = 0; i < num; i++) {
						ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
							"dbus call %s returned group %s", DBUS_SSSD_GET_USER_GROUPS_METHOD, ptr[i]);
						*(char **)apr_array_push(values) = ptr[i];
					}
					if (num && the_config->output_groups) {
						lookup_identity_output_data(r, the_output, the_config->output_groups, values, the_config->output_groups_sep);
					}
					if (the_config->output_groups_iter) {
						lookup_identity_output_iter(r, the_output, the_config->output_groups_iter, values);
					}
					dbus_free_string_array(ptr);
				}
				if (reply) {
					dbus_message_unref(reply);
				}
				if (dbus_error_is_set(&error)) {
					dbus_error_free(&error);
				}
			}
			if (the_config->output_user_attr) {
				apr_hash_t * seen = NULL;
				if (the_config->output_user_attr_iter) {
					seen = apr_hash_make(r->pool);
				}
				DBusMessage * reply = lookup_identity_dbus_message(r, connection, &error, the_timeout,
					DBUS_SSSD_GET_USER_ATTR_METHOD, the_config->output_user_attr);
				if (reply) {
					DBusMessageIter iter;
					dbus_message_iter_init(reply, &iter);
					int type = dbus_message_iter_get_arg_type(&iter);
					if (type == DBUS_TYPE_ARRAY) {
						dbus_message_iter_recurse(&iter, &iter);
						do {
							type = dbus_message_iter_get_arg_type(&iter);
							if (type != DBUS_TYPE_DICT_ENTRY) {
								ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
									"dbus call %s returned value %d instead of DBUS_TYPE_DICT_ENTRY",
									DBUS_SSSD_GET_USER_ATTR_METHOD, type);
								continue;
							}
							DBusMessageIter dictiter;
							dbus_message_iter_recurse(&iter, &dictiter);
							char * attr_name;
							dbus_message_iter_get_basic(&dictiter, &attr_name);
							char * out_name = apr_hash_get(the_config->output_user_attr, attr_name, APR_HASH_KEY_STRING);
							if (!out_name) {
								ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
									"dbus call %s returned key %s that we did not ask for",
									DBUS_SSSD_GET_USER_ATTR_METHOD, attr_name);
								continue;
							}
							if (seen) {
								apr_hash_set(seen, attr_name, APR_HASH_KEY_STRING, "");
							}
							if (! dbus_message_iter_next(&dictiter)) {
								ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
									"dbus call %s returned key %s with no value", DBUS_SSSD_GET_USER_ATTR_METHOD, attr_name);
							}
							type = dbus_message_iter_get_arg_type(&dictiter);
							if (type != DBUS_TYPE_VARIANT) {
								ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
									"dbus call %s returned key %s which does not have DBUS_TYPE_VARIANT as value",
									DBUS_SSSD_GET_USER_ATTR_METHOD, attr_name);
								continue;
							}
							dbus_message_iter_recurse(&dictiter, &dictiter);
							type = dbus_message_iter_get_arg_type(&dictiter);
							if (type != DBUS_TYPE_ARRAY) {
								ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
									"dbus call %s returned key %s which does not have DBUS_TYPE_VARIANT DBUS_TYPE_ARRAY as value",
									DBUS_SSSD_GET_USER_ATTR_METHOD, attr_name);
								continue;
							}
							dbus_message_iter_recurse(&dictiter, &dictiter);
							char * out_sep = the_config->output_user_attr_sep
								? apr_hash_get(the_config->output_user_attr_sep, attr_name, APR_HASH_KEY_STRING)
								: NULL;
							char * out_name_iter = the_config->output_user_attr_iter
								? apr_hash_get(the_config->output_user_attr_iter, attr_name, APR_HASH_KEY_STRING)
								: NULL;

							apr_array_header_t * values = NULL;
							do {
								char * r_data;
								dbus_message_iter_get_basic(&dictiter, &r_data);
								ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
									"dbus call %s returned attr %s=%s", DBUS_SSSD_GET_USER_ATTR_METHOD, attr_name, r_data);
								if (! values) {
									values = apr_array_make(r->pool, 1, sizeof(char *));
								}
								*(char **)apr_array_push(values) = r_data;
							} while (dbus_message_iter_next(&dictiter));
							if (values && strlen(out_name)) {
								lookup_identity_output_data(r, the_output, out_name, values, out_sep);
							}
							if (out_name_iter) {
								lookup_identity_output_iter(r, the_output, out_name_iter, values);
							}
						} while (dbus_message_iter_next(&iter));
					}
					dbus_message_unref(reply);
				}
				if (the_config->output_user_attr_iter) {
					apr_hash_index_t * hi = apr_hash_first(r->pool, the_config->output_user_attr_iter);
					while (hi) {
						const void * key;
						void * value;
						apr_hash_this(hi, &key, NULL, &value);
						if (! apr_hash_get(seen, key, APR_HASH_KEY_STRING)) {
							lookup_identity_output_iter(r, the_output, value, NULL);
						}
						hi = apr_hash_next(hi);
					}
				}
			}
			dbus_connection_unref(connection);
		}
		dbus_error_free(&error);
	}
#endif

	return OK;
}

APR_DECLARE_OPTIONAL_FN(int, lookup_identity_hook, (request_rec * r));

static const char * set_output(cmd_parms * cmd, void * conf_void, const char * arg) {
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

#ifndef NO_USER_ATTR
static const char * set_output_groups(cmd_parms * cmd, void * conf_void, const char * arg, const char * sep) {
	lookup_identity_config * cfg = (lookup_identity_config *) conf_void;
	if (cfg) {
		cfg->output_groups = apr_pstrdup(cmd->pool, arg);
		if (sep) {
			cfg->output_groups_sep = apr_pstrdup(cmd->pool, sep);
		}
	}
	return NULL;
}

static const char * set_user_attr(cmd_parms * cmd, void * conf_void, const char * attrib, const char * output, const char * sep) {
	lookup_identity_config * cfg = (lookup_identity_config *) conf_void;
	if (cfg) {
		if (!cfg->output_user_attr) {
			cfg->output_user_attr = apr_hash_make(cmd->pool);
		}
		char * key = apr_pstrdup(cmd->pool, attrib);
		apr_hash_set(cfg->output_user_attr, key, APR_HASH_KEY_STRING, apr_pstrdup(cmd->pool, output));
		if (sep) {
			if (!cfg->output_user_attr_sep) {
				cfg->output_user_attr_sep = apr_hash_make(cmd->pool);
			}
			apr_hash_set(cfg->output_user_attr_sep, key, APR_HASH_KEY_STRING, apr_pstrdup(cmd->pool, sep));
		}
	}
	return NULL;
}

static const char * set_user_attr_iter(cmd_parms * cmd, void * conf_void, const char * attrib, const char * output) {
	lookup_identity_config * cfg = (lookup_identity_config *) conf_void;
	if (cfg) {
		if (!cfg->output_user_attr_iter) {
			cfg->output_user_attr_iter = apr_hash_make(cmd->pool);
		}
		char * key = apr_pstrdup(cmd->pool, attrib);
		apr_hash_set(cfg->output_user_attr_iter, key, APR_HASH_KEY_STRING, apr_pstrdup(cmd->pool, output));
		if (!cfg->output_user_attr) {
			cfg->output_user_attr = apr_hash_make(cmd->pool);
		}
		if (! apr_hash_get(cfg->output_user_attr, key, APR_HASH_KEY_STRING)) {
			apr_hash_set(cfg->output_user_attr, key, APR_HASH_KEY_STRING, "");
		}
	}
	return NULL;
}
#endif

static lookup_identity_config * create_common_conf(apr_pool_t * pool) {
	lookup_identity_config * cfg = apr_pcalloc(pool, sizeof(lookup_identity_config));
	if (cfg) {
		cfg->output = LOOKUP_IDENTITY_OUTPUT_DEFAULT;
		cfg->output_gecos = LOOKUP_IDENTITY_OUTPUT_GECOS;
	}
	return cfg;
}

static void * create_server_conf(apr_pool_t * pool, server_rec * s) {
	lookup_identity_config * cfg = create_common_conf(pool);
	if (cfg)
		cfg->context = apr_psprintf(pool, "(server %s)", s->server_hostname);
	return cfg;
}

static void * create_dir_conf(apr_pool_t * pool, char * context) {
	lookup_identity_config * cfg = create_common_conf(pool);
	if (cfg) {
		context = context ? context : "(no directory context)";
		cfg->context = apr_pstrdup(pool, context);
	}
	return cfg;
}

static void * merge_dir_conf(apr_pool_t * pool, void * base_void, void * add_void) {
	lookup_identity_config * base = (lookup_identity_config *) base_void;
	lookup_identity_config * add = (lookup_identity_config *) add_void;
	lookup_identity_config * cfg = (lookup_identity_config *) create_dir_conf(pool, add->context);
	cfg->output = (add->output == LOOKUP_IDENTITY_OUTPUT_DEFAULT) ? base->output : add->output;
	cfg->output_gecos = add->output_gecos ? add->output_gecos : base->output_gecos;
#ifndef NO_USER_ATTR
	cfg->output_groups = add->output_groups ? add->output_groups : base->output_groups;
	cfg->output_groups_sep = add->output_groups_sep ? add->output_groups_sep : base->output_groups_sep;
	cfg->output_groups_iter = add->output_groups_iter ? add->output_groups_iter : base->output_groups_iter;
	if (base->output_user_attr) {
		if (add->output_user_attr) {
			cfg->output_user_attr = apr_hash_overlay(pool, add->output_user_attr, base->output_user_attr);
		} else {
			cfg->output_user_attr = base->output_user_attr;
		}
	} else if (add->output_user_attr) {
		cfg->output_user_attr = add->output_user_attr;
	}
	if (base->output_user_attr_sep) {
		if (add->output_user_attr_sep) {
			cfg->output_user_attr_sep = apr_hash_overlay(pool, add->output_user_attr_sep, base->output_user_attr_sep);
		} else {
			cfg->output_user_attr_sep = base->output_user_attr_sep;
		}
	} else if (add->output_user_attr_sep) {
		cfg->output_user_attr_sep = add->output_user_attr_sep;
	}
	if (base->output_user_attr_iter) {
		if (add->output_user_attr_iter) {
			cfg->output_user_attr_iter = apr_hash_overlay(pool, add->output_user_attr_iter, base->output_user_attr_iter);
		} else {
			cfg->output_user_attr_iter = base->output_user_attr_iter;
		}
	} else if (add->output_user_attr_iter) {
		cfg->output_user_attr_iter = add->output_user_attr_iter;
	}
	cfg->dbus_timeout = add->dbus_timeout ? add->dbus_timeout : base->dbus_timeout;
#endif
	return cfg;
}

static const command_rec directives[] = {
	AP_INIT_TAKE1("LookupOutput", set_output, NULL, RSRC_CONF | ACCESS_CONF, "Specify where the lookup results should be stored (note or variable)"),
	AP_INIT_TAKE1("LookupUserGECOS", ap_set_string_slot, (void*)APR_OFFSETOF(lookup_identity_config, output_gecos), RSRC_CONF | ACCESS_CONF, "Name of the note/variable for the GECOS information"),
#ifndef NO_USER_ATTR
	AP_INIT_TAKE12("LookupUserGroups", set_output_groups, NULL, RSRC_CONF | ACCESS_CONF, "Name of the note/variable for the group information"),
	AP_INIT_TAKE1("LookupUserGroupsIter", ap_set_string_slot, (void*)APR_OFFSETOF(lookup_identity_config, output_groups_iter), RSRC_CONF | ACCESS_CONF, "Name of the notes/variables for the group information"),
	AP_INIT_TAKE23("LookupUserAttr", set_user_attr, NULL, RSRC_CONF | ACCESS_CONF, "Additional user attribute (attr, note/variable name, separator)"),
	AP_INIT_TAKE2("LookupUserAttrIter", set_user_attr_iter, NULL, RSRC_CONF | ACCESS_CONF, "Additional user attributes (attr, note/variable name)"),
	AP_INIT_TAKE1("LookupDbusTimeout", ap_set_int_slot, (void*)APR_OFFSETOF(lookup_identity_config, dbus_timeout), RSRC_CONF | ACCESS_CONF, "Timeout for sssd dbus calls (in ms)"),
#endif
	{ NULL }
};

static void register_hooks(apr_pool_t * pool) {
	static const char * const aszSucc[] = {"mod_headers.c", NULL};
	ap_hook_fixups(lookup_identity_hook, NULL, aszSucc, APR_HOOK_LAST);
	APR_REGISTER_OPTIONAL_FN(lookup_identity_hook);
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

