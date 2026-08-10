#ifndef OPENMLS_CLI_H
#define OPENMLS_CLI_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Client OpenMlsCli;

OpenMlsCli *openmls_cli_new(void);
void openmls_cli_free(OpenMlsCli *client);
void openmls_cli_string_free(char *value);

char *openmls_cli_register(OpenMlsCli *client, const char *name);
char *openmls_cli_load(OpenMlsCli *client, const char *name);
char *openmls_cli_create_key_package(OpenMlsCli *client);
char *openmls_cli_create_group(OpenMlsCli *client);
char *openmls_cli_update(OpenMlsCli *client);
char *openmls_cli_info(OpenMlsCli *client);
char *openmls_cli_update_group(OpenMlsCli *client, const char *group);
char *openmls_cli_group_info(OpenMlsCli *client, const char *group);
char *openmls_cli_resolve_group(OpenMlsCli *client, const char *prefix);
char *openmls_cli_invite(OpenMlsCli *client, const char *group, const char *user);
char *openmls_cli_remove(OpenMlsCli *client, const char *group, const char *user);
char *openmls_cli_promote(OpenMlsCli *client, const char *group, const char *user);
char *openmls_cli_demote(OpenMlsCli *client, const char *group, const char *user);
char *openmls_cli_leave(OpenMlsCli *client, const char *group);
char *openmls_cli_self_update(OpenMlsCli *client, const char *group);
char *openmls_cli_send(OpenMlsCli *client, const char *group, const char *message);
char *openmls_cli_read(OpenMlsCli *client, const char *group);
char *openmls_cli_reset(OpenMlsCli *client);

#ifdef __cplusplus
}
#endif

#endif
