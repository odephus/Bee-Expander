#include "state.h"
#include <string.h>
#include <wchar.h>
BOOL StateInit(AppState *state, const wchar_t *path, const Vault *vault) {
    if (wcslen(path)>=MAX_PATH || !ValidVault(vault)) return FALSE;
    InitializeSRWLock(&state->lock);
    InitializeSRWLock(&state->write_lock);
    state->vault=*vault;
    memcpy(state->path,path,(wcslen(path)+1u)*sizeof(wchar_t));
    state->revision=1;
    return TRUE;
}
void StateSnapshot(AppState *state, Vault *out, uint32_t *revision) {
    AcquireSRWLockShared(&state->lock);
    *out=state->vault; *revision=state->revision;
    ReleaseSRWLockShared(&state->lock);
}
BOOL StateCommit(AppState *state, const Vault *next, uint32_t revision) {
    BOOL ok=FALSE;
    wchar_t path[MAX_PATH];
    AcquireSRWLockExclusive(&state->write_lock);
    AcquireSRWLockShared(&state->lock);
    BOOL current=state->revision==revision;
    memcpy(path,state->path,sizeof(path));
    ReleaseSRWLockShared(&state->lock);
    /* Serialize writers, but keep the hook's read lock free during DPAPI/disk I/O. */
    if (current && SaveVaultToFile(path,next,FALSE)) {
        AcquireSRWLockExclusive(&state->lock);
        SecureZeroMemory(&state->vault,sizeof(state->vault));
        state->vault=*next; ++state->revision; ok=TRUE;
        ReleaseSRWLockExclusive(&state->lock);
    }
    ReleaseSRWLockExclusive(&state->write_lock);
    return ok;
}
BOOL StateMatch(AppState *state, const wchar_t *buffer, wchar_t *password, size_t *trigger_length) {
    BOOL found=FALSE;
    size_t length=wcslen(buffer);
    if (!TryAcquireSRWLockShared(&state->lock)) return FALSE;
    for (uint32_t i=0; i<state->vault.count; ++i) {
        wchar_t tag[TAG_CAP];
        int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,state->vault.items[i].tag,-1,tag,TAG_CAP);
        if (n>1 && (size_t)(n-1)<=length && !wcscmp(buffer+length-(size_t)(n-1),tag)) {
            memcpy(password,state->vault.items[i].password,PASSWORD_CAP*sizeof(wchar_t));
            *trigger_length=(size_t)(n-1); found=TRUE; break;
        }
    }
    ReleaseSRWLockShared(&state->lock);
    return found;
}
