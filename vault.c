#include "vault.h"
#include <wincrypt.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static const BYTE magic[8] = {'B','E','E','V','L','T','\r','\n'};
#define RECORD_BYTES (TAG_CAP + PASSWORD_CAP * 2u)
#define PLAIN_MAX (4u + MAX_VAULT_ITEMS * RECORD_BYTES)

static uint32_t Read32(const BYTE *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void Write32(BYTE *p, uint32_t n) {
    p[0]=(BYTE)n; p[1]=(BYTE)(n>>8); p[2]=(BYTE)(n>>16); p[3]=(BYTE)(n>>24);
}
BOOL ValidItem(const VaultItem *item) {
    const char *end = (const char *)memchr(item->tag, 0, TAG_CAP);
    size_t n = 0;
    wchar_t tag[TAG_CAP];
    if (!end || end == item->tag) return FALSE;
    for (const char *p=item->tag; p<end; ++p) if ((unsigned char)*p < 32u || *p == 127) return FALSE;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, item->tag, -1, tag, TAG_CAP)) return FALSE;
    while (n < PASSWORD_CAP && item->password[n]) ++n;
    if (n == PASSWORD_CAP) return FALSE;
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, item->password, -1, NULL, 0, NULL, NULL) > 0;
}
BOOL ValidVault(const Vault *vault) {
    if (vault->count > MAX_VAULT_ITEMS) return FALSE;
    for (uint32_t i=0; i<vault->count; ++i) {
        if (!ValidItem(&vault->items[i])) return FALSE;
        for (uint32_t j=0; j<i; ++j) if (!strcmp(vault->items[i].tag, vault->items[j].tag)) return FALSE;
    }
    return TRUE;
}
static BOOL DecodePlain(const BYTE *data, DWORD size, Vault *out) {
    uint32_t count;
    if (size < 4u) return FALSE;
    count = Read32(data);
    if (count > MAX_VAULT_ITEMS || size != 4u + count * RECORD_BYTES) return FALSE;
    out->count = count;
    for (uint32_t i=0; i<count; ++i) {
        const BYTE *record = data + 4u + i * RECORD_BYTES;
        memcpy(out->items[i].tag, record, TAG_CAP);
        for (uint32_t j=0; j<PASSWORD_CAP; ++j)
            out->items[i].password[j] = (wchar_t)((unsigned)record[TAG_CAP+2u*j] | ((unsigned)record[TAG_CAP+2u*j+1u]<<8));
    }
    return ValidVault(out);
}
static VaultResult ReadFileBounded(const wchar_t *path, BYTE **bytes, DWORD *length) {
    LARGE_INTEGER size;
    DWORD read = 0;
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND ? VAULT_MISSING : VAULT_IO;
    if (!GetFileSizeEx(f, &size)) { CloseHandle(f); return VAULT_IO; }
    if (size.QuadPart < 4 || size.QuadPart > VAULT_MAX_FILE) { CloseHandle(f); return VAULT_INVALID; }
    *length = (DWORD)size.QuadPart;
    *bytes = (BYTE *)calloc(*length, 1);
    if (!*bytes) { CloseHandle(f); return VAULT_IO; }
    BOOL ok = ReadFile(f, *bytes, *length, &read, NULL) && read == *length;
    if (!CloseHandle(f)) ok = FALSE;
    return ok ? VAULT_OK : VAULT_IO;
}
VaultResult LoadVaultFromFile(const wchar_t *path, Vault *out) {
    BYTE *bytes = NULL;
    DWORD length = 0;
    Vault candidate = {0};
    DATA_BLOB plain = {0}, encrypted = {0};
    VaultResult result = ReadFileBounded(path, &bytes, &length);
    if (result != VAULT_OK) goto done;
    if (length >= sizeof(magic) && !memcmp(bytes, magic, sizeof(magic))) {
        if (length < 16u || Read32(bytes+8) != 1u || Read32(bytes+12) != length-16u) { result=VAULT_INVALID; goto done; }
        encrypted.pbData = bytes+16; encrypted.cbData=length-16u;
        if (!CryptUnprotectData(&encrypted, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &plain)) { result=VAULT_INVALID; goto done; }
        result = (plain.cbData <= PLAIN_MAX && DecodePlain(plain.pbData, plain.cbData, &candidate)) ? VAULT_OK : VAULT_INVALID;
    } else {
        result = DecodePlain(bytes, length, &candidate) ? VAULT_LEGACY : VAULT_INVALID;
    }
    /* Legacy contents are never activated until explicit migration succeeds. */
    if (result == VAULT_OK) *out=candidate;
done:
    SecureZeroMemory(&candidate, sizeof(candidate));
    if (plain.pbData) { SecureZeroMemory(plain.pbData, plain.cbData); LocalFree(plain.pbData); }
    if (bytes) { SecureZeroMemory(bytes, length); free(bytes); }
    return result;
}
BOOL AtomicWrite(const wchar_t *path, const BYTE *data, DWORD length, BOOL create_only) {
    wchar_t temp[MAX_PATH], backup[MAX_PATH], suffix[33];
    BYTE random[16];
    BOOL ok, preserve_temp=FALSE;
    DWORD written = 0;
    if (wcslen(path) + 38u >= MAX_PATH) return FALSE;
    if (BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return FALSE;
    for (size_t i=0; i<sizeof(random); ++i) swprintf(suffix+2u*i, 3, L"%02x", (unsigned)random[i]);
    if (swprintf(temp, MAX_PATH, L"%ls.%ls.tmp", path, suffix) < 0 ||
        swprintf(backup, MAX_PATH, L"%ls.%ls.bak", path, suffix) < 0) return FALSE;
    HANDLE f = CreateFileW(temp, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    ok = WriteFile(f, data, length, &written, NULL) && written == length && FlushFileBuffers(f);
    if (!CloseHandle(f)) ok=FALSE;
    if (ok) {
        DWORD attrs = GetFileAttributesW(path);
        if (create_only || attrs == INVALID_FILE_ATTRIBUTES)
            ok = MoveFileExW(temp, path, MOVEFILE_WRITE_THROUGH);
        else {
            /* ReplaceFile can fail after renaming the old file. Always supply a
               recovery name; never delete the last recoverable copy on failure. */
            ok = ReplaceFileW(path, temp, backup, 0, NULL, NULL);
            if (ok) DeleteFileW(backup);
            else {
                if (GetFileAttributesW(path)==INVALID_FILE_ATTRIBUTES &&
                    GetFileAttributesW(backup)!=INVALID_FILE_ATTRIBUTES)
                    (void)MoveFileExW(backup,path,MOVEFILE_WRITE_THROUGH);
                preserve_temp=GetFileAttributesW(path)==INVALID_FILE_ATTRIBUTES;
            }
        }
    }
    if (!ok && !preserve_temp) DeleteFileW(temp);
    /* If the destination vanished and recovery failed, retain temp/backup. */
    return ok;
}
BOOL SaveVaultToFile(const wchar_t *path, const Vault *vault, BOOL create_only) {
    BYTE *plain = NULL, *file = NULL;
    DATA_BLOB input = {0}, encrypted = {0};
    BOOL ok=FALSE;
    if (!ValidVault(vault)) return FALSE;
    input.cbData=4u + vault->count * RECORD_BYTES;
    plain=(BYTE *)calloc(input.cbData, 1);
    if (!plain) goto done;
    input.pbData=plain; Write32(plain, vault->count);
    for (uint32_t i=0; i<vault->count; ++i) {
        BYTE *record=plain+4u+i*RECORD_BYTES;
        memcpy(record, vault->items[i].tag, strlen(vault->items[i].tag));
        for (size_t j=0; j<wcslen(vault->items[i].password); ++j) {
            record[TAG_CAP+2u*j]=(BYTE)vault->items[i].password[j];
            record[TAG_CAP+2u*j+1u]=(BYTE)((unsigned)vault->items[i].password[j]>>8);
        }
    }
    if (!CryptProtectData(&input, L"Bee Expander vault", NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &encrypted)) goto done;
    if (encrypted.cbData > VAULT_MAX_FILE-16u) goto done;
    file=(BYTE *)malloc(16u+encrypted.cbData);
    if (!file) goto done;
    memcpy(file, magic, sizeof(magic)); Write32(file+8, 1); Write32(file+12, encrypted.cbData);
    memcpy(file+16, encrypted.pbData, encrypted.cbData);
    ok=AtomicWrite(path, file, 16u+encrypted.cbData, create_only);
done:
    if (plain) { SecureZeroMemory(plain, input.cbData); free(plain); }
    if (encrypted.pbData) { SecureZeroMemory(encrypted.pbData, encrypted.cbData); LocalFree(encrypted.pbData); }
    free(file);
    return ok;
}
BOOL MigrateLegacyVault(const wchar_t *path, Vault *out) {
    wchar_t backup[MAX_PATH];
    BYTE *bytes=NULL;
    DWORD length=0;
    Vault candidate={0};
    BOOL ok=FALSE;
    /* Hold source against writes/deletes until the exclusive backup is complete. */
    HANDLE guard=CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (guard == INVALID_HANDLE_VALUE) return FALSE;
    if (wcslen(path)+12u >= MAX_PATH || swprintf(backup, MAX_PATH, L"%ls.legacy.bak", path) < 0) goto done;
    if (ReadFileBounded(path, &bytes, &length) != VAULT_OK || !DecodePlain(bytes, length, &candidate)) goto done;
    if (!CopyFileW(path, backup, TRUE)) goto done;
    CloseHandle(guard); guard=INVALID_HANDLE_VALUE;
    if (!SaveVaultToFile(path, &candidate, FALSE)) goto done;
    *out=candidate; ok=TRUE;
done:
    if (guard != INVALID_HANDLE_VALUE) CloseHandle(guard);
    if (bytes) { SecureZeroMemory(bytes, length); free(bytes); }
    SecureZeroMemory(&candidate, sizeof(candidate));
    return ok;
}
