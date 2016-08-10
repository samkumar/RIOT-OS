/*
 * Copyright (C) 2016 University of California, Berkeley
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     task_sched
 * @{
 *
 * @file
 * @brief       TinyOS-style task scheduler
 *
 * @author      Sam Kumar <samkumar@berkeley.edu>
 *
 * This module, built on top of the xtimer module, emulates a TinyOS-style task
 * scheduler in a single thread.
 *
 * Tasks in TinyOS execute in an event loop. When a task is "posted", it is
 * placed at the back of the event queue, unless that task is already on the
 * event queue, in which case nothing happens.
 *
 * This is slightly different from messages in RIOT's IPC mechanism in that a
 * task can only exist in the event queue in one place. This has the advantage
 * that the memory needed for the event queue is bounded by the number of
 * different tasks.
 * @}
 */

#include <mutex.h>
#include <stdbool.h>
#include <string.h>
#include <task_sched.h>
#include <thread.h>
#include <xtimer.h>

#include "debug.h"

msg_t expired = { 0, 0, { 0 } };

void* _task_sched(void* arg)
{
    struct task_sched* sched = arg;
    int64_t until_next = 0;

    msg_t msg;
    msg_t msg_queue[1];

    msg_init_queue(msg_queue, 1);

    while (1) {
        msg_receive(&msg);

        mutex_lock(&sched->_lock);
        sched->_in_process_loop = true;

        while (sched->_first != -1 && (until_next =
            (int64_t) (sched->tasks[sched->_first]._exec_time - xtimer_now64()))
                        <= sched->coalesce_thresh) {
            int taskid = sched->_first;
            struct task* t = &sched->tasks[sched->_first];
            assert(t->_prev == -1);
            sched->_first = t->_next;
            t->_next = -1;

            /* Process the task. */
            mutex_unlock(&sched->_lock);
            sched->task_handler(taskid);
            mutex_lock(&sched->_lock);
        }

        /* Schedule the next timer, if any. */
        xtimer_remove(&sched->_timer);
        if (sched->_first != -1) {
            xtimer_set_msg64(&sched->_timer, (uint64_t) until_next, &expired,
                             sched->_pid);
        }

        sched->_in_process_loop = false;
        mutex_unlock(&sched->_lock);
    }

    /* Not reached */
    return NULL;
}

kernel_pid_t start_task_sched(struct task_sched* args)
{
    int i;
    for (i = 0; i < args->num_tasks; i++) {
        args->tasks[i]._next = -1;
        args->tasks[i]._prev = -1;
    }
    mutex_init(&args->_lock);
    memset(&args->_timer, 0x00, sizeof(xtimer_t));
    args->_first = -1;
    args->_in_process_loop = false;
    args->_pid = thread_create(args->thread_stack, args->thread_stack_size,
                               args->thread_priority, THREAD_CREATE_STACKTEST,
                               _task_sched, args, args->thread_name);
    return args->_pid;
}

static int _sched_task(struct task_sched* sched, int taskid, bool cancel,
                        int64_t delay);

int sched_task(struct task_sched* sched, int taskid, int64_t delay)
{
    return _sched_task(sched, taskid, false, delay);
}

int cancel_task(struct task_sched* sched, int taskid)
{
    return _sched_task(sched, taskid, true, 0);
}

static int _sched_task(struct task_sched* sched, int taskid, bool cancel,
                        int64_t delay)
{
    uint64_t now;
    struct task* t;
    int oldfirst = sched->_first;

    if (taskid < 0 || taskid > sched->num_tasks) {
        return -1;
    }

    t = &sched->tasks[taskid];

    mutex_lock(&sched->_lock);

    /* Remove the task from the queue. */
    if (t->_prev != -1) {
        sched->tasks[t->_prev]._next = t->_next;
    } else {
        sched->_first = t->_next;
    }
    if (t->_next != -1) {
        sched->tasks[t->_next]._prev = t->_prev;
    }

    now = xtimer_now64();

    if (cancel) {

        t->_prev = -1;
        t->_next = -1;

    } else {

        int curr;
        int prev = -1;

        /* Find the correct place in the queue. */
        for (curr = sched->_first; curr != -1; curr = sched->tasks[curr]._next) {
            if (delay > (int64_t) (sched->tasks[curr]._exec_time - now)) {
                break;
            }
            prev = curr;
        }

        /* Put the task at the correct place in the queue. */
        t->_prev = prev;
        t->_next = curr;
        if (curr != -1) {
            sched->tasks[curr]._prev = taskid;
        }
        if (t->_prev != -1) {
            sched->tasks[t->_prev]._next = taskid;
        } else {
            sched->_first = taskid;
        }

        /* Correctly set the exec time. */
        t->_exec_time = now + (uint64_t) delay;
    }

    /*
     * If the head of the queue changed, reset the timer so the correct
     * event fires (unless we're in the precessing loop; then we'll check
     * anyway, so don't bother with sending a message).
     */
    xtimer_remove(&sched->_timer);
    if (!sched->_in_process_loop && sched->_first != -1
        && (sched->_first == taskid || oldfirst == taskid)) {

        // If the next event is sufficiently close, just fire it.
        int64_t delay_to_first = sched->tasks[sched->_first]._exec_time - now;
        if (delay_to_first <= sched->coalesce_thresh) {
            msg_try_send(&expired, sched->_pid);
        } else {
            xtimer_set_msg64(&sched->_timer, delay_to_first, &expired,
                             sched->_pid);
        }
    }

    mutex_unlock(&sched->_lock);
    return 0;
}
