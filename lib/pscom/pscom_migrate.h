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

#ifndef _PSCOM_MIGRATE_H_
#define _PSCOM_MIGRATE_H_
#include "pscom_priv.h"

#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <mosquitto.h>

#define PSCOM_MOSQUITTO_CLIENT_NAME_LENGTH 	50
#define PSCOM_MOSQUITTO_TOPIC_LENGTH 		50
#define PSCOM_MOSQUITTO_REQ_TOPIC 		"fast/pscom/<hostname>/<pid>/request"
#define PSCOM_MOSQUITTO_RESP_TOPIC 		"fast/pscom/<hostname>/<pid>/response"
#define PSCOM_BROKER_HOST 			"devon"
#define PSCOM_BROKER_PORT 			1883
#define PSCOM_KEEP_ALIVE_INT 			60


/* initialize/cleanup migration module */
int pscom_migration_init(void);
int pscom_migration_cleanup(void);

/* suspend/resume plugins that cannot be migrated with a VM */
int pscom_suspend_non_migratable_plugins(void);
int pscom_resume_non_migratable_plugins(void);

/* react to shutdown/resume request from MigFra */
void pscom_migration_handle_shutdown_req(void);
void pscom_migration_handle_resume_req(void);

/* inform MigFra that resume is complete */
void pscom_report_to_migfra(const char *status);
#endif /* _PSCOM_MIGRATE_H_ */
