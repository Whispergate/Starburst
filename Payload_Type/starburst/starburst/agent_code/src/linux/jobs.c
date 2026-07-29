#include "starburst.h"

typedef struct {
    char     task_uuid[40];
    uint8_t  cmd_id;
    void    *(*func)(void *);
    void    *arg;
} job_thread_arg_t;

static void *job_wrapper(void *raw) {
    job_thread_arg_t *jta = (job_thread_arg_t *)raw;
    jta->func(jta->arg);
    job_complete(jta->task_uuid);
    free(jta);
    return NULL;
}

int job_create(const char *task_uuid, uint8_t cmd_id, void *(*func)(void *), void *arg) {
    pthread_mutex_lock(&g_state.jobs_mutex);

    int slot = -1;
    for (int i = 0; i < MAX_JOBS; i++) {
        if (!g_state.jobs[i].active) { slot = i; break; }
    }

    if (slot < 0) {
        pthread_mutex_unlock(&g_state.jobs_mutex);
        queue_response(task_uuid, RSP_ERROR, "no job slots available");
        return -1;
    }

    job_entry_t *job = &g_state.jobs[slot];
    memset(job, 0, sizeof(*job));
    strncpy(job->task_uuid, task_uuid, 39);
    job->cmd_id = cmd_id;
    job->status = JOB_STATUS_RUNNING;
    job->active = 1;

    job_thread_arg_t *jta = (job_thread_arg_t *)calloc(1, sizeof(job_thread_arg_t));
    strncpy(jta->task_uuid, task_uuid, 39);
    jta->cmd_id = cmd_id;
    jta->func = func;
    jta->arg = arg;

    if (pthread_create(&job->thread, NULL, job_wrapper, jta) != 0) {
        job->active = 0;
        free(jta);
        pthread_mutex_unlock(&g_state.jobs_mutex);
        queue_response(task_uuid, RSP_ERROR, "pthread_create failed");
        return -1;
    }

    pthread_detach(job->thread);
    pthread_mutex_unlock(&g_state.jobs_mutex);

    DBG("job_create: slot=%d cmd=0x%02x uuid=%.8s", slot, cmd_id, task_uuid);
    return slot;
}

void job_complete(const char *task_uuid) {
    pthread_mutex_lock(&g_state.jobs_mutex);
    for (int i = 0; i < MAX_JOBS; i++) {
        if (g_state.jobs[i].active && strcmp(g_state.jobs[i].task_uuid, task_uuid) == 0) {
            g_state.jobs[i].status = JOB_STATUS_COMPLETE;
            g_state.jobs[i].active = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_state.jobs_mutex);
}

void cmd_jobkill_handler(const char *task_uuid, parser_t *params) {
    char *target_uuid = pr_string(params);

    pthread_mutex_lock(&g_state.jobs_mutex);
    for (int i = 0; i < MAX_JOBS; i++) {
        if (g_state.jobs[i].active && strcmp(g_state.jobs[i].task_uuid, target_uuid) == 0) {
            pthread_cancel(g_state.jobs[i].thread);
            g_state.jobs[i].active = 0;
            g_state.jobs[i].status = JOB_STATUS_COMPLETE;
            pthread_mutex_unlock(&g_state.jobs_mutex);
            queue_response(task_uuid, RSP_SUCCESS, "job killed");
            free(target_uuid);
            return;
        }
    }
    pthread_mutex_unlock(&g_state.jobs_mutex);

    queue_response(task_uuid, RSP_ERROR, "job not found");
    free(target_uuid);
}
