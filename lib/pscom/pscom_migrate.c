/*
 * ParaStation
 *
 * Copyright (C) 2007 ParTec Cluster Competence Center GmbH, Munich
 *
 * This file may be distributed under the terms of the Q Public License
 * as defined in the file LICENSE.QPL included in the packaging of this
 * file.
 *
 * Author:	Simon Pickartz <spickartz@eonerc.rwth-aachen.de>
 */

#include "pscom_migrate.h"
#include "pscom_con.h"
#include "pscom_str_util.h"
#include "pscom_io.h"
#include "pscom_queues.h"
#include "pscom_req.h"
#include "pslib.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <errno.h>

#define _PSCOM_SUPPORT_MIGRATION
#ifdef _PSCOM_SUPPORT_MIGRATION

static int pscom_mosquitto_initialized;
static struct mosquitto *pscom_mosquitto_client;
static  char pscom_mosquitto_req_topic[PSCOM_MOSQUITTO_TOPIC_LENGTH] = PSCOM_MOSQUITTO_REQ_TOPIC;
static  char pscom_mosquitto_resp_topic[PSCOM_MOSQUITTO_TOPIC_LENGTH] = PSCOM_MOSQUITTO_RESP_TOPIC;

static inline int
pscom_str_replace(char *search_str, char *replace_str, char *str)
{
	char *tmp_str, *search_start;
	int str_len = 0;

	/* find search_str in str */
	if ((search_start = strstr(str, search_str)) == NULL) {
		return -1;
	}

	/* allocate memory */
	if ((tmp_str = (char*)malloc(strlen(str) * sizeof(char))) == NULL) {
		return -1;
	}

	/* copy original  and compute string length */
	strcpy(tmp_str, str);
	str_len = search_start - str;
	str[str_len] = '\0';


	strcat(str, replace_str);
	str_len += strlen(search_str);
	strcat(str, (char*)tmp_str+str_len);

	free(tmp_str);

	return 0;
}


static
int pscom_suspend_plugins(void)
{	
	struct list_head *pos_sock;
	struct list_head *pos_con;
	int arch;
	pscom_plugin_t *plugin;

	/*
	 * Shutdown connections first
	 */

	/* iterate over all sockets */
	list_for_each(pos_sock, &pscom.sockets) {
		pscom_sock_t *sock = list_entry(pos_sock, pscom_sock_t, next);

		/* suspend listen FD: */
		pscom_suspend_listen(&sock->pub);

		/* iterate over all connections */
		struct list_head *tmp_con;
		list_for_each_safe(pos_con, tmp_con, &sock->connections) {
			pscom_con_t *con = list_entry(pos_con,
			    			      pscom_con_t, 
						      next);
	
			/* determine corresponding plugin */
			arch = PSCOM_CON_TYPE2ARCH(con->pub.type);
		 	plugin = pscom_plugin_by_archid(arch);
			
			/* suspend all still pending on-demand connections, too */
			if(con->pub.type == PSCOM_CON_TYPE_ONDEMAND) {
				con->read_suspend(con);
				con->write_suspend(con);
			}

			/* go to next connection if plugin not set */
			if (plugin == NULL)
				continue;

			/* shutdown the connection if not migratable */
			if (plugin->properties & 
			    PSCOM_PLUGIN_PROP_NOT_MIGRATABLE) {
	
				pscom_con_shutdown(con);	

				/* wait for response */
				while ( (con->read_is_suspended == 0) || (con->write_is_suspended == 0) ) {
					con->read_start(con);
					con->write_start(con);
					pscom_test_any();
				}
			}
		}
	}

	/*
	 * Shutdown non-migratable plugins
	 */

	DPRINT(1, "%s %u: Find non-migratable plugins ...", __FILE__, __LINE__);
	struct list_head *pos_plugin;
	list_for_each(pos_plugin, &pscom_plugins) {
		plugin = list_entry(pos_plugin, pscom_plugin_t, next);

		if ((plugin->properties & PSCOM_PLUGIN_PROP_NOT_MIGRATABLE) &&
		    (plugin->destroy)) {
			DPRINT(1, 
			       "%s %u: Destroying '%s' ...", 
			       __FILE__, 
			       __LINE__,
			       plugin->name);
			if(plugin->destroy) {
				plugin->destroy();
			}
			DPRINT(1, 
			       "%s %u: Successfully destroyed '%s'!", 
			       __FILE__, 
			       __LINE__,
			       plugin->name);
		}
	}

	return 0;
}


int pscom_suspend_non_migratable_plugins(void)
{
	int ret;
	pscom_lock(); {
		ret = pscom_suspend_plugins();
	} pscom_unlock();
	return ret;
}


static
int pscom_resume_plugins(void)
{
	struct list_head *pos_sock;
	struct list_head *pos_con;
	int arch;
	pscom_plugin_t *plugin;

	/* iterate over all sockets */
	list_for_each(pos_sock, &pscom.sockets) {
		pscom_sock_t *sock = list_entry(pos_sock, pscom_sock_t, next);

		/* resume listen FD: */
		pscom_resume_listen(&sock->pub);

		/* iterate over all connections */
		list_for_each(pos_con, &sock->connections) {
			pscom_con_t *con = list_entry(pos_con,
			    			      pscom_con_t, 
						      next);
			/* resume connections */
			pscom_resume_connection(&con->pub);	
		}
	}

	return PSCOM_SUCCESS;
}

int pscom_resume_non_migratable_plugins(void)
{
	pscom_lock(); {
		pscom_resume_plugins();
	} pscom_unlock();

	return PSCOM_SUCCESS;
}

static
void pscom_message_callback(struct mosquitto *mosquitto_client, 
    				 void *arg, 
				 const struct mosquitto_message *message)
{
	int pid = -1;
	int my_pid = getpid();
	char* msg;
	char payload[PSCOM_MOSQUITTO_TOPIC_LENGTH] = {[0 ... PSCOM_MOSQUITTO_TOPIC_LENGTH-1] = 0};

	if ((char*)message->payload) {
		strcpy(payload, (char*)message->payload);

		if (!strcmp(payload, "*")) {
			pid = -2;
		} else {
			msg = strtok(payload, " ");
	
			while (msg) {
				sscanf(msg, "%d", &pid);
				if (pid == my_pid)
					break;
				msg = strtok(NULL, " ");
			}
		}
	} else {
		pid = -2;
	}
	

	if (pid == my_pid || pid == -2) {

		DPRINT(1, "\nINFO: Got MQTT message: %s (Found my PID %d)\n", payload, my_pid);

		switch (pscom.migration_state) {
		case PSCOM_MIGRATION_INACTIVE:
			pscom.migration_state = PSCOM_MIGRATION_REQUESTED;
			DPRINT(2, "\nSTATE: PSCOM_MIGRATION_INACTIVE -> "
 				  "PSCOM_MIGRATION_REQUESTED");
			break;
		case PSCOM_MIGRATION_ALLOWED:
			pscom.migration_state = PSCOM_MIGRATION_FINISHED;
			DPRINT(2, "STATE: PSCOM_MIGRATION_ALLOWED -> "
 				  "PSCOM_MIGRATION_FINISHED");
			break;
		case PSCOM_MIGRATION_PREPARING:
			DPRINT(2, "STATE: PSCOM_MIGRATION_PREPARING -> "
				  "!WARNING! Didn't change state!");
//			assert(0);
			break;
		case PSCOM_MIGRATION_FINISHED:
			DPRINT(2, "STATE: PSCOM_MIGRATION_FINISHED -> "
				  "!WARNING! Didn't change state!");
//			assert(0);
			break;
		case PSCOM_MIGRATION_REQUESTED:
			DPRINT(2, "STATE: PSCOM_MIGRATION_REQUESTED -> "
				  "!WARNING! Didn't change state!");
//			assert(0);
			break;
		case PSCOM_MIGRATION_RESUMING:
			DPRINT(2, "STATE: PSCOM_MIGRATION_RESUMING -> "
				  "!WARNING! Didn't change state!");
//			assert(0);
			break;

		default:	
			DPRINT(1, "%s %d: ERROR: Unknown migration state (%d). "
				  "Abort!", 
				  __FILE__, __LINE__, 
				  pscom.migration_state);
			assert(0);
		}
	} else {
		DPRINT(1, "\nINFO: Got MQTT message: %s (Didn't find my PID %d)\n", payload, my_pid);
	}
}


void pscom_report_to_migfra(const char *status)
{
	char state[] = "65536 : COMPLETED";
	sprintf(state, "%d : %s", getpid(), status);

	int err = mosquitto_publish(pscom_mosquitto_client,
				    NULL,
				    pscom_mosquitto_resp_topic,
				    sizeof(state),
				    (const void*)state,
				    1,
				    false);
	if (err != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "%s %d: ERROR: Could not publish on '%s' - %d"
		       "(%d [%s])",
		       __FILE__, __LINE__,
		       PSCOM_MOSQUITTO_RESP_TOPIC,
		       err,
		       errno,
		       strerror(errno));
		exit(-1);
	}
	
	/* reset migration state */
	pscom.migration_state = PSCOM_MIGRATION_INACTIVE;
}

void pscom_migration_handle_resume_req(void)
{
	DPRINT(1, "INFO: Handling resume request ...\n");
	pscom_resume_non_migratable_plugins();
	DPRINT(1, "INFO: Resume Complete!\n");

	/* reset migration state */
	pscom.migration_state = PSCOM_MIGRATION_RESUMING;

	DPRINT(3, "[%d] ||||||||||||||| MIGRATON COMPLETED ||||||||||||||", getpid());


	/* report to migration framework of feedback should not be postponed */
	if (pscom.env.postpone_feedback == 0) {
		pscom_report_to_migfra("COMPLETED");
	}
}

void pscom_migration_handle_shutdown_req(void)
{
	/* change migration state */
	pscom.migration_state = PSCOM_MIGRATION_PREPARING;

	DPRINT(1, "INFO: Handling shutdown request ...\n");
	pscom_suspend_non_migratable_plugins();
	DPRINT(1, "INFO: Shutdown complete!\n");

	/* change migration state */
	pscom.migration_state = PSCOM_MIGRATION_ALLOWED;

	DPRINT(3, "[%d] !!!!!!!!!!!!!!! MIGRATON ALLOWED !!!!!!!!!!!!!!!", getpid());

	char state[] = "65536 : ALLOWED";
	sprintf(state, "%d : ALLOWED", getpid());

	/* inform migration-framework */
	int err = mosquitto_publish(pscom_mosquitto_client,
	    			    NULL,
				    pscom_mosquitto_resp_topic,
				    sizeof(state),
				    (const void*)state,
				    0,
				    false);
	if (err != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "%s %d: ERROR: Could not publish on '%s' - %d"
		       "(%d [%s])", 
		       __FILE__, __LINE__,
		       PSCOM_MOSQUITTO_RESP_TOPIC,
		       err,
		       errno, 
		       strerror(errno));
		exit(-1);
	}

	/* wait until the migration has terminated */
	while (pscom.migration_state != PSCOM_MIGRATION_FINISHED) {
		sched_yield();
	}

	/* resume the connections now */	
	pscom_migration_handle_resume_req();
}

int pscom_migration_init(void)
{
	pscom_mosquitto_initialized = 0;

	/* leave if feature should be disabled */
	if (pscom.env.suspend_resume == 0)
		return 0;
	
	/* initialize libmosquitto */
	if (mosquitto_lib_init() != MOSQ_ERR_SUCCESS) {
		DPRINT(1, "%s %d: ERROR: Could not init libmosquitto ",
		       __FILE__, __LINE__);
		return PSCOM_ERR_STDERROR;
	}

	/* create a new mosquitto client */	
	char client_name[PSCOM_MOSQUITTO_CLIENT_NAME_LENGTH];
	char my_pid[10];
	sprintf(my_pid, "_%d", getpid());
	gethostname(client_name, PSCOM_MOSQUITTO_CLIENT_NAME_LENGTH);
	strcat(client_name, my_pid);
	pscom_mosquitto_client = mosquitto_new(client_name, 
	    				       true,
					       NULL);
	if (pscom_mosquitto_client == NULL) {
		DPRINT(1, "%s %d: ERROR: Could create new mosquitto client "
		       "instance (%d [%s])", 
		       __FILE__, __LINE__,
		       errno, 
		       strerror(errno));
		return PSCOM_ERR_STDERROR;
	}
	
	/* connect to mosquitto broker in BLOCKING manner */
	int err;
	err = mosquitto_connect(pscom_mosquitto_client,
				PSCOM_BROKER_HOST,
				PSCOM_BROKER_PORT,
			      	PSCOM_KEEP_ALIVE_INT);
	if ( err != MOSQ_ERR_SUCCESS) {
		DPRINT(1, "%s %d: ERROR: Could connect to the broker - %d"
		       "(%d [%s])", 
		       __FILE__, __LINE__,
		       err,
		       errno, 
		       strerror(errno));
		return PSCOM_ERR_STDERROR;
	} else {
		DPRINT(1, "Connected to the Mosquitto broker");
	}

	/* determine hostname and PID */
	char hostname[PSCOM_MOSQUITTO_CLIENT_NAME_LENGTH];
	gethostname(hostname, PSCOM_MOSQUITTO_CLIENT_NAME_LENGTH);
	char pid[PSCOM_MOSQUITTO_CLIENT_NAME_LENGTH];
	sprintf(pid, "%d", getpid());

	/* create topics */
	pscom_str_replace("<hostname>", hostname, pscom_mosquitto_req_topic);
	pscom_str_replace("<pid>", "+", pscom_mosquitto_req_topic);
	pscom_str_replace("<hostname>", hostname, pscom_mosquitto_resp_topic);
	pscom_str_replace("<pid>", pid, pscom_mosquitto_resp_topic);

	/* subscribe to the migration command topic */
	err = mosquitto_subscribe(pscom_mosquitto_client,
				  NULL,
				  pscom_mosquitto_req_topic,
				  0);
	if (err != MOSQ_ERR_SUCCESS) {
		DPRINT(1, "%s %d: ERROR: Could not subscribe to '%s' - %d"
		       "(%d [%s])", 
		       __FILE__, __LINE__,
		       pscom_mosquitto_req_topic,
		       err,
		       errno, 
		       strerror(errno));
		return PSCOM_ERR_STDERROR;
	}

	DPRINT(1, "INFO: Subscribing to '%s'", pscom_mosquitto_req_topic);
	DPRINT(1, "INFO: Publishing  on '%s'", pscom_mosquitto_resp_topic);

	/* set the subscription callback */
	mosquitto_message_callback_set(pscom_mosquitto_client,
				       &pscom_message_callback);
	
	/* start the communication loop */
	err = mosquitto_loop_start(pscom_mosquitto_client);
	if ( err != MOSQ_ERR_SUCCESS) {
		DPRINT(1, "%s %d: ERROR: Could not start the communication "
		       "loop - %d",
		       __FILE__, __LINE__,
		       err);
		return PSCOM_ERR_STDERROR;
	}

	pscom_mosquitto_initialized = 1;
	return PSCOM_SUCCESS;
}

int pscom_migration_cleanup(void)
{
	int err;

	/* unsubscribe from the migration command topic */	
	err = mosquitto_unsubscribe(pscom_mosquitto_client,
				    NULL,
				    PSCOM_MOSQUITTO_REQ_TOPIC);
	if (err != MOSQ_ERR_SUCCESS) {
		DPRINT(1, "%s %d: ERROR: Could not unsubscribe from '%s' - %d"
		       "(%d [%s])", 
		       __FILE__, __LINE__,
		       PSCOM_MOSQUITTO_REQ_TOPIC,
		       err,
		       errno, 
		       strerror(errno));
		return PSCOM_ERR_STDERROR;
	}


	/* disconnect from broker */
	err = mosquitto_disconnect(pscom_mosquitto_client);
	if (err != MOSQ_ERR_SUCCESS) {
		DPRINT(1, "%s %d: ERROR: Could not disconnect from broker "
		       "- %d",
		       __FILE__, __LINE__,
		       err);
		return PSCOM_ERR_STDERROR;
	}

	/* stop the communication loop */
	err = mosquitto_loop_stop(pscom_mosquitto_client, false);
	if (err != MOSQ_ERR_SUCCESS) {
		DPRINT(1, "%s %d: ERROR: Could not stop the communication loop "
		       "- %d",
		       __FILE__, __LINE__,
		       err);
		return PSCOM_ERR_STDERROR;
	}

	/* destroy the mosquitto client */	
	mosquitto_destroy(pscom_mosquitto_client);

	/* cleanup libmosquitto */
	if (mosquitto_lib_cleanup() != MOSQ_ERR_SUCCESS) {
		DPRINT(1, "%s %d: ERROR: Could not cleanup libmosquitto ",
		       __FILE__, __LINE__);
	}

	return PSCOM_SUCCESS;
}

#else
int pscom_migration_init(void)
{
	return 0;
}
int pscom_migration_cleanup(void)
{
	return 0;
}
void pscom_migration_handle_shutdown_req(void)
{
	return;
}

void pscom_report_to_migfra(const char *status)
{
	return;
}
#endif /* _PSCOM_SUPPORT_MIGRATION */
