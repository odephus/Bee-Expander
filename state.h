#ifndef BEE_STATE_H
#define BEE_STATE_H
#include "vault.h"
typedef struct {
    SRWLOCK lock, write_lock;
    Vault vault;
    wchar_t path[MAX_PATH];
    uint32_t revision;
} AppState;
BOOL StateInit(AppState *state, const wchar_t *path, const Vault *vault);
void StateSnapshot(AppState *state, Vault *out, uint32_t *revision);
BOOL StateCommit(AppState *state, const Vault *next, uint32_t revision);
/* Non-blocking: the low-level hook must never wait on disk I/O. */
BOOL StateMatch(AppState *state, const wchar_t *buffer, wchar_t *password, size_t *trigger_length);
#endif
