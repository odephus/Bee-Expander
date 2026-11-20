# Bee Expander

Native C / Win32 tray utility with Turkish and English UI at
http://127.0.0.1:7200/. Requires Windows 10 version 1607 or later. Runs without
administrator privileges.

## Build and test

MinGW-w64 GCC in PATH, from PowerShell:

~~~powershell
.\build.ps1 -Test
~~~

Outputs: build/bee-expander.exe and build/bee-tests.exe.
The build uses C11, strict warnings as errors, stack protection, ASLR/NX, and
static compiler support libraries. Only Windows system DLLs are required.

Alternatively, install Visual Studio 2022 C++ desktop tools and Windows SDK:

~~~bat
build-msvc.cmd
build-msvc.cmd asan
~~~

The first command builds and tests the release application with /W4 /WX /sdl
and Control Flow Guard. The second builds separate *-asan.exe artifacts with
Windows AddressSanitizer; run these from the configured developer environment.
Both scripts link Crypt32, BCrypt, Ws2_32, User32, Shell32, and Advapi32.

Tests use generated synthetic data in unique build/test-* folders and an ephemeral
loopback port. They never launch the tray application, install keyboard hooks,
read a user vault, or write autostart registry settings. Coverage includes DPAPI
round trips, empty/full vaults, invalid record counts and strings, truncated and
oversized files, invalid headers, corrupted ciphertext, explicit legacy migration,
write failures and recovery, URL/form/HTTP bounds, HTML escaping, CSRF/Host/Origin,
fragmented/incomplete socket requests, concurrent state access, stale deletions,
Unicode matching, location changes and shutdown. A deterministic 10,000-input
malformed parsing corpus also runs. Assertion totals vary with randomized DPAPI
output and TCP fragmentation.

Interactive smoke checks remain necessary: tray open/exit, Turkish/English
keyboard layouts, insertion into intended applications, autostart, and the
migration confirmation dialog. Tests deliberately do not inject text into the
user's active application.

## Vault storage and migration

The default location remains %APPDATA%\BeeExpander\vault.dat; config.txt retains
a custom location. Configuration is written as UTF-8; older Windows-codepage
configuration is accepted. Missing vaults start empty with no default credential.
Unreadable, malformed, or undecryptable vaults stop startup without rewriting them.

Version 1 uses an 8-byte BEEVLT CR LF magic, a little-endian uint32 version,
a little-endian uint32 ciphertext length, and the DPAPI payload. Decrypted data
contains a uint32 count and canonical records of 32 UTF-8 tag bytes and 128
little-endian UTF-16 password code units. Counts, terminators, encoding and exact
lengths are checked; the maximum is 50 records, 31 UTF-8 bytes per trigger
(including surrounding dots), and 127 UTF-16 units per password. Tags without
surrounding double dots are wrapped when added. Duplicate tags are rejected.

For an old plaintext vault:

1. Exit every old Bee Expander instance and retain a private recovery copy.
2. Confirm the intended file is in the configured vault folder (or the default
   folder when no config exists). For a vault elsewhere, update config.txt to its
   existing absolute local folder while the app is stopped; do not overwrite any
   other vault. The location-change button is not an import operation. Run the
   new build under the Windows account that will use the vault.
3. Accept the explicit migration prompt. Declining exits without changes.
4. Migration validates the entire legacy file, creates vault.dat.legacy.bak
   without overwriting an existing backup, and saves the DPAPI version.
5. Verify the new vault, then remove the plaintext backup and other plaintext
   copies according to your storage/backup policy. Deletion does not guarantee
   physical erasure on SSDs, snapshots, or synchronized storage.

If migration fails, keep the original and backup. Do not delete them or start an
old binary against the encrypted file. An existing .legacy.bak blocks migration;
verify and retain it under a different private name before retrying. Malformed
legacy files require separate recovery; they are never silently truncated.

DPAPI is scoped to the Windows user and usually the computer. Copying vault.dat
alone is not a supported cross-device migration. This release does not implement
portable export/import: retain access to the original Windows context and
manually recreate entries on the target, or implement and review an explicit
authenticated encrypted export/import workflow first. See Microsoft's
[DPAPI documentation](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).

Saves use exclusive random temporary files, flush them, then replace the
destination with a recovery backup. Rare replacement failures can leave
vault.dat.<random>.bak or .tmp recovery files: retain them until the active vault
has been verified. The same mechanism protects configuration writes. A location
change requires a short absolute local drive path and never overwrites a
destination vault. It retains the previous encrypted vault. If the configuration
write fails, the active location stays unchanged and the newly created encrypted
copy is retained for recovery.

## Security and behavior

- Passwords never appear in HTML responses; only a fixed mask is rendered.
  There is no browser reveal endpoint. Entry fields use password input controls.
- Every action uses POST with a per-launch random CSRF token. The server binds
  exclusively to 127.0.0.1:7200 and requires that exact Host, with same-origin
  Origin for POST. Forms from a previous launch must be refreshed.
- HTTP requests are bounded (8 KiB headers, 4 KiB bodies, five-second read
  deadline), require explicit framing, and reject chunked transfer and pipelining.
  Responses disable caching/framing and restrict content with CSP.
- Vault updates become visible only after a successful save. Hook readers
  operate on synchronized snapshots without waiting on disk I/O. Old deletion
  forms are rejected if the vault changed.
- Expansion uses Unicode SendInput instead of placing passwords on the clipboard.
  No automatic elevation occurs; elevated applications and some custom/IME input
  controls may not accept insertion. Partial insertion reports an error without
  retrying the secret. Ordinary single-character keyboard translation is
  supported; IME composition and multi-code-unit trigger keystrokes are not.
- This is protection at rest and against cross-origin websites, not an isolation
  boundary against same-user malware, administrators, debugger access, or
  applications into which text is expanded. Decrypted entries remain in process
  memory during use. Local processes can access the local UI and obtain its
  token. A single-client server can still suffer bounded local denial of service.
- Close older versions before running this build. Do not concurrently edit the
  same vault from another Windows session or external process.
- The credential formerly committed in source must be treated as exposed.
  Rotate it wherever it was used. Rotation and any coordinated Git-history
  cleanup require separate user action; this change does neither.

Next useful improvements are reviewed portable encrypted export/import, recovery
UI for malformed legacy files, cross-session vault locking, and broader manual
keyboard/IME application compatibility testing.
