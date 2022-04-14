#include <chcore/internal/raw_syscall.h>
#include <sync/spin.h>
#include "mutex.h"
#include <stdio.h>

int sem;

void lock_init(struct lock *lock)
{
        /* LAB 4 TODO BEGIN */
        sem = __chcore_sys_create_sem();
        __chcore_sys_signal_sem(sem);
        /* LAB 4 TODO END */
}

void lock(struct lock *lock)
{
        /* LAB 4 TODO BEGIN */
        __chcore_sys_wait_sem(sem, 1);
        /* LAB 4 TODO END */
}

void unlock(struct lock *lock)
{
        /* LAB 4 TODO BEGIN */
        __chcore_sys_signal_sem(sem);
        /* LAB 4 TODO END */
}
