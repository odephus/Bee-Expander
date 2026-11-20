@echo off
setlocal
cd /d "%~dp0"
if not defined VSCMD_VER (
    if not exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" exit /b 1
    for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do call "%%i\VC\Auxiliary\Build\vcvars64.bat"
)
if not defined VSCMD_VER exit /b 1
if not exist build mkdir build
set "BEE_FLAGS=/nologo /std:c11 /utf-8 /W4 /WX /sdl /MT /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 /D_CRT_SECURE_NO_WARNINGS /Zi"
set "BEE_DIAGNOSTICS=/O2 /guard:cf"
set "BEE_SUFFIX="
set "BEE_LINK_DIAGNOSTICS=/guard:cf"
if /i "%~1"=="asan" (
    set "BEE_DIAGNOSTICS=/Od /fsanitize=address"
    set "BEE_SUFFIX=-asan"
    set "BEE_LINK_DIAGNOSTICS="
)
set "BEE_LIBS=crypt32.lib bcrypt.lib ws2_32.lib user32.lib shell32.lib advapi32.lib"
cl %BEE_FLAGS% %BEE_DIAGNOSTICS% main.c vault.c http.c state.c /Fobuild\ /Fdbuild\app%BEE_SUFFIX%.pdb /Febuild\bee-expander-msvc%BEE_SUFFIX%.exe /link %BEE_LINK_DIAGNOSTICS% /SUBSYSTEM:WINDOWS /DYNAMICBASE /NXCOMPAT %BEE_LIBS%
if errorlevel 1 exit /b 1
cl %BEE_FLAGS% %BEE_DIAGNOSTICS% tests\tests.c vault.c http.c state.c /Fobuild\ /Fdbuild\tests%BEE_SUFFIX%.pdb /Febuild\bee-tests-msvc%BEE_SUFFIX%.exe /link %BEE_LINK_DIAGNOSTICS% /SUBSYSTEM:CONSOLE /DYNAMICBASE /NXCOMPAT %BEE_LIBS%
if errorlevel 1 exit /b 1
build\bee-tests-msvc%BEE_SUFFIX%.exe
exit /b %errorlevel%
