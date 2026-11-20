#ifndef BEE_VAULT_H
#define BEE_VAULT_H
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#define MAX_VAULT_ITEMS 50u
#define TAG_CAP 32u
#define PASSWORD_CAP 128u
#define VAULT_MAX_FILE 65536u
typedef struct { char tag[TAG_CAP]; wchar_t password[PASSWORD_CAP]; } VaultItem;
typedef struct { uint32_t count; VaultItem items[MAX_VAULT_ITEMS]; } Vault;
typedef enum { VAULT_OK, VAULT_MISSING, VAULT_LEGACY, VAULT_INVALID, VAULT_IO } VaultResult;
BOOL ValidItem(const VaultItem *item);
BOOL ValidVault(const Vault *vault);
VaultResult LoadVaultFromFile(const wchar_t *path, Vault *out);
BOOL SaveVaultToFile(const wchar_t *path, const Vault *vault, BOOL create_only);
/* Explicit opt-in only. Leaves an exclusive .legacy.bak plaintext backup. */
BOOL MigrateLegacyVault(const wchar_t *path, Vault *out);
BOOL AtomicWrite(const wchar_t *path, const BYTE *data, DWORD length, BOOL create_only);
#endif
