param([switch]$Test)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    New-Item -ItemType Directory -Path build -Force | Out-Null
    $flags = @('-std=c11', '-O2', '-Wall', '-Wextra', '-Wpedantic', '-Wconversion', '-Wshadow', '-Wformat=2', '-Werror', '-DUNICODE', '-D_UNICODE', '-D_WIN32_WINNT=0x0A00', '-fstack-protector-strong', '-static', '-Wl,--dynamicbase,--nxcompat,--high-entropy-va')
    $libs = @('-lcrypt32', '-lbcrypt', '-lws2_32', '-luser32', '-lshell32', '-ladvapi32')
    & gcc @flags main.c vault.c http.c state.c -o build/bee-expander.exe -mwindows @libs
    if ($LASTEXITCODE -ne 0) { throw 'Application build failed.' }
    if ($Test) {
        & gcc @flags tests/tests.c vault.c http.c state.c -o build/bee-tests.exe @libs
        if ($LASTEXITCODE -ne 0) { throw 'Test build failed.' }
        & ./build/bee-tests.exe
        if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
    }
} finally { Pop-Location }
