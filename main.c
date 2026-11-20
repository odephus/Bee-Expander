#include "http.h"
#include "state.h"
#include <shellapi.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>

#define WM_TRAYICON (WM_USER + 1)
#define WM_INPUT_ERROR (WM_USER + 2)
#define WM_SERVER_ERROR (WM_USER + 3)
#define IDM_OPEN_UI 1001
#define IDM_EXIT 1002
#define KEY_CAP 64u
#define PAGE_CAP 65536u

static AppState app;
static volatile LONG current_lang;
static wchar_t config_path[MAX_PATH], vault_dir[MAX_PATH], key_buffer[KEY_CAP];
static char csrf[65];
static HANDLE stop_event;
static SOCKET listener=INVALID_SOCKET;
static HWND app_window;
static NOTIFYICONDATAW nid;
static HWND last_foreground;

static const char *Text(const char *tr, const char *en) {
    return InterlockedCompareExchange(&current_lang,0,0)==0 ? tr : en;
}
static void Alert(const wchar_t *message) {
    MessageBoxW(app_window,message,L"Bee Expander",MB_OK|MB_ICONERROR);
}
static BOOL JoinPath(wchar_t *out, const wchar_t *dir, const wchar_t *name) {
    if (wcslen(dir)+wcslen(name)+2u >= MAX_PATH-38u) return FALSE;
    return swprintf(out,MAX_PATH,L"%ls\\%ls",dir,name)>0;
}
static BOOL DirectoryExists(const wchar_t *dir) {
    DWORD attrs=GetFileAttributesW(dir);
    return attrs!=INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)!=0;
}
static BOOL LocalDirectory(const wchar_t *dir) {
    size_t n=wcslen(dir);
    /* No UNC, device namespaces, alternate streams, or relative paths. */
    if (n<3u || n>=MAX_PATH-60u || !((dir[0]>=L'A' && dir[0]<=L'Z') || (dir[0]>=L'a' && dir[0]<=L'z')) ||
        dir[1]!=L':' || dir[2]!=L'\\') return FALSE;
    for (size_t i=2; i<n; ++i) if (dir[i]<32 || wcschr(L":*?\"<>|/",dir[i])) return FALSE;
    return TRUE;
}
static BOOL InitPaths(wchar_t *vault_path) {
    wchar_t base[MAX_PATH];
    char cfg[MAX_PATH*4u]={0};
    if (FAILED(SHGetFolderPathW(NULL,CSIDL_APPDATA,NULL,SHGFP_TYPE_CURRENT,base)) ||
        !JoinPath(vault_dir,base,L"BeeExpander")) return FALSE;
    if (!CreateDirectoryW(vault_dir,NULL) && GetLastError()!=ERROR_ALREADY_EXISTS) return FALSE;
    if (!DirectoryExists(vault_dir) || !JoinPath(config_path,vault_dir,L"config.txt")) return FALSE;
    HANDLE f=CreateFileW(config_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if (f!=INVALID_HANDLE_VALUE) {
        LARGE_INTEGER size;
        DWORD read=0;
        BOOL ok=GetFileSizeEx(f,&size) && size.QuadPart>0 && size.QuadPart<(LONGLONG)sizeof(cfg) &&
            ReadFile(f,cfg,(DWORD)size.QuadPart,&read,NULL) && read==(DWORD)size.QuadPart;
        if (!CloseHandle(f)) ok=FALSE;
        if (!ok || memchr(cfg,0,read)) return FALSE;
        while (read && (cfg[read-1u]=='\r' || cfg[read-1u]=='\n')) cfg[--read]=0;
        /* Older configuration used the active Windows codepage. */
        if (!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,cfg,-1,vault_dir,MAX_PATH) &&
            !MultiByteToWideChar(CP_ACP,0,cfg,-1,vault_dir,MAX_PATH)) return FALSE;
    } else if (GetLastError()!=ERROR_FILE_NOT_FOUND) return FALSE;
    return LocalDirectory(vault_dir) && DirectoryExists(vault_dir) && JoinPath(vault_path,vault_dir,L"vault.dat");
}
static BOOL IsAutoStartEnabled(void) {
    HKEY key;
    DWORD type=0,size=0;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_QUERY_VALUE,&key)!=ERROR_SUCCESS) return FALSE;
    LONG result=RegQueryValueExW(key,L"BeeExpander",NULL,&type,NULL,&size);
    RegCloseKey(key);
    return result==ERROR_SUCCESS && type==REG_SZ && size>sizeof(wchar_t);
}
static BOOL ToggleAutoStart(BOOL enable) {
    HKEY key;
    wchar_t path[MAX_PATH], quoted[MAX_PATH+3u];
    LONG result;
    if (RegCreateKeyExW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,NULL,0,KEY_SET_VALUE,NULL,&key,NULL)!=ERROR_SUCCESS) return FALSE;
    if (enable) {
        DWORD n=GetModuleFileNameW(NULL,path,MAX_PATH);
        if (!n || n>=MAX_PATH || swprintf(quoted,MAX_PATH+3u,L"\"%ls\"",path)<0) { RegCloseKey(key); return FALSE; }
        result=RegSetValueExW(key,L"BeeExpander",0,REG_SZ,(const BYTE *)quoted,(DWORD)((wcslen(quoted)+1u)*sizeof(wchar_t)));
    } else {
        result=RegDeleteValueW(key,L"BeeExpander");
        if (result==ERROR_FILE_NOT_FOUND) result=ERROR_SUCCESS;
    }
    RegCloseKey(key);
    return result==ERROR_SUCCESS;
}
static BOOL MoveVault(const char *utf8) {
    wchar_t dir[MAX_PATH], path[MAX_PATH], canonical[MAX_PATH];
    char encoded[MAX_PATH*4u];
    if (!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,utf8,-1,dir,MAX_PATH) || !LocalDirectory(dir)) return FALSE;
    DWORD n=GetFullPathNameW(dir,MAX_PATH,canonical,NULL);
    if (!n || n>=MAX_PATH || !LocalDirectory(canonical)) return FALSE;
    if (!_wcsicmp(canonical,vault_dir)) return TRUE;
    if (!CreateDirectoryW(canonical,NULL) && GetLastError()!=ERROR_ALREADY_EXISTS) return FALSE;
    if (!DirectoryExists(canonical) || !JoinPath(path,canonical,L"vault.dat")) return FALSE;
    int bytes=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,canonical,-1,encoded,sizeof(encoded),NULL,NULL);
    if (bytes<=1) return FALSE;
    Vault snapshot;
    uint32_t revision;
    AcquireSRWLockExclusive(&app.write_lock);
    StateSnapshot(&app,&snapshot,&revision);
    /* Never overwrite a vault in the destination; retain the old vault as recovery. */
    BOOL ok=SaveVaultToFile(path,&snapshot,TRUE);
    if (ok) ok=AtomicWrite(config_path,(const BYTE *)encoded,(DWORD)(bytes-1),FALSE);
    if (ok) {
        AcquireSRWLockExclusive(&app.lock);
        memcpy(app.path,path,(wcslen(path)+1u)*sizeof(wchar_t));
        memcpy(vault_dir,canonical,(wcslen(canonical)+1u)*sizeof(wchar_t));
        ++app.revision;
        ReleaseSRWLockExclusive(&app.lock);
    }
    ReleaseSRWLockExclusive(&app.write_lock);
    SecureZeroMemory(&snapshot,sizeof(snapshot));
    return ok;
}
static BOOL DoReplaceText(size_t trigger_len, const wchar_t *new_text) {
    INPUT inputs[(TAG_CAP+PASSWORD_CAP)*2u]={0};
    UINT count=0;
    size_t length=0;
    while (length<PASSWORD_CAP && new_text[length]) ++length;
    if (!trigger_len || trigger_len>=TAG_CAP || length>=PASSWORD_CAP) return FALSE;
    for (size_t i=1; i<trigger_len; ++i) {
        inputs[count].type=INPUT_KEYBOARD; inputs[count++].ki.wVk=VK_BACK;
        inputs[count].type=INPUT_KEYBOARD; inputs[count].ki.wVk=VK_BACK;
        inputs[count++].ki.dwFlags=KEYEVENTF_KEYUP;
    }
    /* Unicode input avoids leaving secrets in the clipboard or its history. */
    for (size_t i=0; i<length; ++i) {
        inputs[count].type=INPUT_KEYBOARD; inputs[count].ki.wScan=new_text[i];
        inputs[count++].ki.dwFlags=KEYEVENTF_UNICODE;
        inputs[count].type=INPUT_KEYBOARD; inputs[count].ki.wScan=new_text[i];
        inputs[count++].ki.dwFlags=KEYEVENTF_UNICODE|KEYEVENTF_KEYUP;
    }
    UINT sent=count ? SendInput(count,inputs,sizeof(INPUT)) : 0;
    if (sent!=count) {
        /* A partial batch may end on a key-down; release that key without retrying the secret. */
        if (sent && !(inputs[sent-1u].ki.dwFlags & KEYEVENTF_KEYUP)) {
            INPUT release=inputs[sent-1u]; release.ki.dwFlags|=KEYEVENTF_KEYUP;
            (void)SendInput(1,&release,sizeof(INPUT));
            SecureZeroMemory(&release,sizeof(release));
        }
        PostMessageW(app_window,WM_INPUT_ERROR,0,0);
    }
    SecureZeroMemory(inputs,sizeof(inputs));
    return sent>0 || count==0;
}
static LRESULT CALLBACK LowLevelKeyboardProc(int code, WPARAM param, LPARAM detail) {
    if (code!=HC_ACTION || param!=WM_KEYDOWN) return CallNextHookEx(NULL,code,param,detail);
    const KBDLLHOOKSTRUCT *key=(const KBDLLHOOKSTRUCT *)detail;
    if (key->flags & LLKHF_INJECTED) return CallNextHookEx(NULL,code,param,detail);
    HWND foreground=GetForegroundWindow();
    if (foreground!=last_foreground) { SecureZeroMemory(key_buffer,sizeof(key_buffer)); last_foreground=foreground; }
    if ((GetAsyncKeyState(VK_CONTROL)|GetAsyncKeyState(VK_MENU)|GetAsyncKeyState(VK_LWIN)|GetAsyncKeyState(VK_RWIN)) & 0x8000) {
        SecureZeroMemory(key_buffer,sizeof(key_buffer));
        return CallNextHookEx(NULL,code,param,detail);
    }
    size_t length=wcslen(key_buffer);
    if (key->vkCode==VK_BACK) {
        if (length) key_buffer[length-1u]=0;
        return CallNextHookEx(NULL,code,param,detail);
    }
    if (key->vkCode==VK_LEFT || key->vkCode==VK_RIGHT || key->vkCode==VK_UP || key->vkCode==VK_DOWN ||
        key->vkCode==VK_HOME || key->vkCode==VK_END || key->vkCode==VK_DELETE || key->vkCode==VK_ESCAPE ||
        key->vkCode==VK_TAB || key->vkCode==VK_RETURN) {
        SecureZeroMemory(key_buffer,sizeof(key_buffer));
        return CallNextHookEx(NULL,code,param,detail);
    }
    BYTE keyboard[256]={0};
    if (!GetKeyboardState(keyboard)) return CallNextHookEx(NULL,code,param,detail);
    keyboard[VK_SHIFT]=(GetAsyncKeyState(VK_SHIFT)&0x8000) ? 0x80 : 0;
    keyboard[VK_CAPITAL]=(BYTE)(GetKeyState(VK_CAPITAL)&1);
    WCHAR chars[4]={0};
    DWORD thread=GetWindowThreadProcessId(foreground,NULL);
    /* Flag 4 avoids altering the dead-key state on Windows 10 1607+. */
    int result=ToUnicodeEx(key->vkCode,key->scanCode,keyboard,chars,4,4,GetKeyboardLayout(thread));
    if (result==1 && chars[0]>=32 && chars[0]!=127) {
        if (length==KEY_CAP-1u) {
            memmove(key_buffer,key_buffer+1,(KEY_CAP-2u)*sizeof(wchar_t)); --length;
        }
        key_buffer[length]=chars[0]; key_buffer[length+1u]=0;
        wchar_t password[PASSWORD_CAP]={0};
        size_t trigger=0;
        BOOL matched=StateMatch(&app,key_buffer,password,&trigger);
        BOOL replaced=FALSE;
        if (matched) {
            SecureZeroMemory(key_buffer,sizeof(key_buffer));
            replaced=DoReplaceText(trigger,password);
        }
        SecureZeroMemory(password,sizeof(password));
        if (replaced) return 1;
    } else if (result!=0) SecureZeroMemory(key_buffer,sizeof(key_buffer));
    return CallNextHookEx(NULL,code,param,detail);
}

typedef struct { char *text; size_t used; BOOL ok; } Page;
static void Append(Page *page, const char *format, ...) {
    if (!page->ok) return;
    va_list args; va_start(args,format);
    int n=vsnprintf(page->text+page->used,PAGE_CAP-page->used,format,args);
    va_end(args);
    if (n<0 || (size_t)n>=PAGE_CAP-page->used) page->ok=FALSE;
    else page->used+=(size_t)n;
}
static void FormStart(Page *page, const char *action) {
    Append(page,"<form method='POST' action='%s'><input type='hidden' name='csrf' value='%s'>",action,csrf);
}
static BOOL RenderPage(char *html) {
    Page page={html,0,TRUE};
    char path_utf8[MAX_PATH*4u], escaped_path[MAX_PATH*24u];
    /* Only tags are copied for rendering. Passwords never enter the page buffer. */
    char tags[MAX_VAULT_ITEMS][TAG_CAP];
    uint32_t count, revision;
    AcquireSRWLockShared(&app.lock);
    count=app.vault.count; revision=app.revision;
    for (uint32_t i=0; i<count; ++i) memcpy(tags[i],app.vault.items[i].tag,TAG_CAP);
    int path_ok=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,app.path,-1,path_utf8,sizeof(path_utf8),NULL,NULL);
    ReleaseSRWLockShared(&app.lock);
    if (!path_ok || !HtmlEscape(path_utf8,escaped_path,sizeof(escaped_path))) return FALSE;
    Append(&page,"<!doctype html><html lang='%s'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Bee Expander</title><style>"
        "*{box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;background:#0f0f0f;color:#e1e1e1;padding:30px 20px;max-width:960px;margin:auto}"
        ".header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #222;margin-bottom:25px}"
        "h2{color:#00ff88;font-size:20px}.header form{display:inline-block;margin:4px}.grid{display:grid;grid-template-columns:320px 1fr;gap:20px}"
        ".card{background:#161616;border:1px solid #222;border-radius:8px;padding:16px;margin-bottom:16px}"
        "h3{color:#888;font-size:12px;text-transform:uppercase}input{width:100%%;padding:9px 12px;margin-bottom:10px;border-radius:5px;border:1px solid #2a2a2a;background:#1f1f1f;color:#fff}"
        "button{padding:9px;border-radius:5px;border:0;background:#00ff88;color:#0f0f0f;font-weight:700;cursor:pointer}"
        ".card button{width:100%%}.path-box{overflow-wrap:anywhere;font:11px monospace;color:#aaa;margin-bottom:10px}"
        "table{width:100%%;border-collapse:collapse}th,td{padding:12px 8px;text-align:left;border-bottom:1px solid #222;font-size:13px}"
        "th{color:#00ff88}.tag-badge{color:#00ff88;font-family:monospace;overflow-wrap:anywhere}.btn-delete{background:#ff4444;color:white}"
        ".note{font-size:12px;color:#aaa;line-height:1.5}@media(max-width:720px){.grid{grid-template-columns:1fr}}</style></head><body>"
        "<div class='header'><h2>⚡ Bee Expander</h2><div>",Text("tr","en"));
    FormStart(&page,"/lang"); Append(&page,"<button name='set' value='tr'>TR</button></form>");
    FormStart(&page,"/lang"); Append(&page,"<button name='set' value='en'>EN</button></form></div></div><div class='grid'><div>");
    Append(&page,"<div class='card'><h3>%s</h3>",Text("Windows ile Başlat","Start with Windows"));
    BOOL autostart=IsAutoStartEnabled();
    FormStart(&page,"/autostart");
    Append(&page,"<button name='set' value='%d'>%s</button></form></div>",!autostart,
        autostart ? Text("Açık — Kapat","Enabled — Disable") : Text("Kapalı — Aç","Disabled — Enable"));
    Append(&page,"<div class='card'><h3>%s</h3><div class='path-box'>%s</div>",Text("Kasa Konumu","Vault Location"),escaped_path);
    FormStart(&page,"/openfolder"); Append(&page,"<button>%s</button></form><br>",Text("Aç","Open"));
    FormStart(&page,"/path");
    Append(&page,"<input name='new_path' placeholder='C:\\Vault' required><button>%s</button></form>"
        "<p class='note'>%s</p></div>",Text("Konumu değiştir","Change location"),
        Text("Hedefte kasa bulunmamalıdır. Eski kasa kurtarma için korunur.","The destination must not contain a vault. The old vault is retained for recovery."));
    Append(&page,"<div class='card'><h3>%s</h3>",Text("Yeni Ekleme","Add New Item"));
    FormStart(&page,"/add");
    Append(&page,"<input name='tag' maxlength='31' placeholder='%s' required>"
        "<input type='password' name='pass' maxlength='127' autocomplete='new-password' placeholder='%s' required>"
        "<button>%s</button></form></div></div><div><div class='card'><table><thead><tr><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody>",
        Text("Tetikleyici Tag","Trigger Tag"),Text("Şifre","Password"),Text("Kasaya Ekle","Add to Vault"),
        Text("Tetikleyici Tag","Trigger Tag"),Text("Kayıtlı Şifre","Saved Password"),Text("İşlem","Action"));
    for (uint32_t i=0; i<count; ++i) {
        char tag[TAG_CAP*6u];
        if (!HtmlEscape(tags[i],tag,sizeof(tag))) return FALSE;
        Append(&page,"<tr><td><span class='tag-badge'>%s</span></td><td>••••••••</td><td>",tag);
        FormStart(&page,"/delete");
        Append(&page,"<input type='hidden' name='revision' value='%lu'><button class='btn-delete' name='index' value='%lu'>%s</button></form></td></tr>",
            (unsigned long)revision,(unsigned long)i,Text("Sil","Delete"));
    }
    Append(&page,"</tbody></table></div><p class='note'>%s</p></div></div></body></html>",
        Text("DPAPI koruması bu Windows kullanıcısına bağlıdır. Cihazlar arası taşıma için açık bir dışa/içe aktarma işlemi gerekir.",
        "DPAPI protection is tied to this Windows user. Moving between devices requires an explicit export/import process."));
    return page.ok;
}
static BOOL Number(const char *s, uint32_t *out) {
    uint32_t n=0;
    if (!*s) return FALSE;
    for (; *s; ++s) {
        if (*s<'0' || *s>'9' || n>(UINT32_MAX-(uint32_t)(*s-'0'))/10u) return FALSE;
        n=n*10u+(uint32_t)(*s-'0');
    }
    *out=n; return TRUE;
}
static int HandlePost(const HttpRequest *request, const char *body) {
    char token[65]={0}, value[MAX_PATH*4u]={0}, password[PASSWORD_CAP*4u]={0};
    Vault next={0};
    uint32_t revision=0;
    int status=400;
    if (!ValidForm(body,request->body_length) ||
        !FormValue(body,request->body_length,"csrf",token,sizeof(token))) { status=403; goto done; }
    unsigned difference=0;
    for (size_t i=0; i<sizeof(csrf); ++i) difference|=(unsigned char)token[i]^(unsigned char)csrf[i];
    if (difference) { status=403; goto done; }
    if (!strcmp(request->path,"/add")) {
        StateSnapshot(&app,&next,&revision);
        if (next.count>=MAX_VAULT_ITEMS) { status=409; goto done; }
        if (!FormValue(body,request->body_length,"tag",value,TAG_CAP) ||
            !FormValue(body,request->body_length,"pass",password,sizeof(password)) || !*value || !*password) goto done;
        VaultItem *item=&next.items[next.count];
        size_t length=strlen(value);
        if (length>=4u && !memcmp(value,"..",2) && !memcmp(value+length-2u,"..",2))
            memcpy(item->tag,value,length+1u);
        else {
            if (length+4u>=TAG_CAP) goto done;
            if (snprintf(item->tag,TAG_CAP,"..%s..",value)<0) goto done;
        }
        if (!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,password,-1,item->password,PASSWORD_CAP)) goto done;
        ++next.count;
        if (!ValidVault(&next)) goto done;
        status=StateCommit(&app,&next,revision) ? 303 : 500;
    } else if (!strcmp(request->path,"/delete")) {
        uint32_t index, expected;
        if (!FormValue(body,request->body_length,"index",value,sizeof(value)) || !Number(value,&index) ||
            !FormValue(body,request->body_length,"revision",value,sizeof(value)) || !Number(value,&expected)) goto done;
        StateSnapshot(&app,&next,&revision);
        if (revision!=expected || index>=next.count) { status=409; goto done; }
        for (uint32_t i=index; i+1u<next.count; ++i) next.items[i]=next.items[i+1u];
        --next.count; SecureZeroMemory(&next.items[next.count],sizeof(VaultItem));
        status=StateCommit(&app,&next,revision) ? 303 : 500;
    } else if (!strcmp(request->path,"/lang")) {
        if (!FormValue(body,request->body_length,"set",value,sizeof(value))) goto done;
        if (!strcmp(value,"tr")) InterlockedExchange(&current_lang,0);
        else if (!strcmp(value,"en")) InterlockedExchange(&current_lang,1);
        else goto done;
        status=303;
    } else if (!strcmp(request->path,"/autostart")) {
        if (!FormValue(body,request->body_length,"set",value,sizeof(value)) || (strcmp(value,"0") && strcmp(value,"1"))) goto done;
        status=ToggleAutoStart(!strcmp(value,"1")) ? 303 : 500;
    } else if (!strcmp(request->path,"/path")) {
        if (!FormValue(body,request->body_length,"new_path",value,sizeof(value))) goto done;
        status=MoveVault(value) ? 303 : 500;
    } else if (!strcmp(request->path,"/openfolder")) {
        status=(INT_PTR)ShellExecuteW(NULL,L"open",vault_dir,NULL,NULL,SW_SHOWNORMAL)>32 ? 303 : 500;
    } else status=404;
done:
    SecureZeroMemory(&next,sizeof(next));
    SecureZeroMemory(token,sizeof(token)); SecureZeroMemory(value,sizeof(value)); SecureZeroMemory(password,sizeof(password));
    return status;
}
static DWORD WINAPI HttpServerThread(LPVOID unused) {
    (void)unused;
    char *buffer=(char *)calloc(HTTP_REQUEST_MAX+1u,1);
    char *page=(char *)calloc(PAGE_CAP,1);
    if (!buffer || !page) { free(buffer); free(page); PostMessageW(app_window,WM_SERVER_ERROR,0,0); return 1; }
    while (WaitForSingleObject(stop_event,0)==WAIT_TIMEOUT) {
        fd_set set; FD_ZERO(&set); FD_SET(listener,&set);
        struct timeval wait={0,100000};
        int ready=select(0,&set,NULL,NULL,&wait);
        if (ready==SOCKET_ERROR) { PostMessageW(app_window,WM_SERVER_ERROR,0,0); break; }
        if (!ready) continue;
        SOCKET client=accept(listener,NULL,NULL);
        if (client==INVALID_SOCKET) { PostMessageW(app_window,WM_SERVER_ERROR,0,0); break; }
        DWORD timeout=1000;
        HttpRequest request={0};
        int status=400;
        const char *response="<p>İstek reddedildi / Request rejected.</p><a href='/'>Geri / Back</a>";
        if (setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,(const char *)&timeout,sizeof(timeout))==0 &&
            ReadRequest(client,stop_event,buffer,&request)) {
            if (request.post) {
                status=HandlePost(&request,buffer+request.header_length);
                if (status==303) response="";
                else if (status==500) response="<p>İşlem kaydedilemedi. Mevcut kasa korundu. / The operation could not be saved. The active vault was preserved.</p><a href='/'>Geri / Back</a>";
            } else if (!strcmp(request.path,"/")) {
                status=RenderPage(page) ? 200 : 500;
                if (status==200) response=page;
            } else status=404;
        }
        /* No request bodies, tokens, or vault contents are logged. */
        (void)SendResponse(client,status,response);
        shutdown(client,SD_BOTH); closesocket(client);
        SecureZeroMemory(buffer,HTTP_REQUEST_MAX+1u); SecureZeroMemory(page,PAGE_CAP);
    }
    SecureZeroMemory(buffer,HTTP_REQUEST_MAX+1u); SecureZeroMemory(page,PAGE_CAP);
    free(buffer); free(page); return 0;
}
static BOOL StartListener(void) {
    struct sockaddr_in address={0};
    BOOL exclusive=TRUE;
    listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (listener==INVALID_SOCKET) return FALSE;
    if (setsockopt(listener,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,(const char *)&exclusive,sizeof(exclusive))!=0) return FALSE;
    address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(7200);
    return bind(listener,(const struct sockaddr *)&address,sizeof(address))==0 && listen(listener,4)==0;
}
static void OpenUI(void) {
    if ((INT_PTR)ShellExecuteW(app_window,L"open",L"http://127.0.0.1:7200/",NULL,NULL,SW_SHOWNORMAL)<=32)
        Alert(L"Tarayıcı açılamadı. / Could not open the browser.");
}
static LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM param, LPARAM detail) {
    if (message==WM_TRAYICON) {
        if (detail==WM_LBUTTONDBLCLK) OpenUI();
        else if (detail==WM_RBUTTONUP) {
            POINT point;
            HMENU menu=CreatePopupMenu();
            if (!menu) return 0;
            BOOL tr=InterlockedCompareExchange(&current_lang,0,0)==0;
            if (GetCursorPos(&point) &&
                AppendMenuW(menu,MF_STRING,IDM_OPEN_UI,tr ? L"Arayüzü Aç" : L"Open Web UI") &&
                AppendMenuW(menu,MF_SEPARATOR,0,NULL) &&
                AppendMenuW(menu,MF_STRING,IDM_EXIT,tr ? L"Çıkış" : L"Exit")) {
                SetForegroundWindow(window);
                UINT cmd=(UINT)TrackPopupMenu(menu,TPM_RETURNCMD|TPM_NONOTIFY,point.x,point.y,0,window,NULL);
                if (cmd==IDM_OPEN_UI) OpenUI();
                else if (cmd==IDM_EXIT) DestroyWindow(window);
                PostMessageW(window,WM_NULL,0,0);
            }
            DestroyMenu(menu);
        }
        return 0;
    }
    if (message==WM_INPUT_ERROR) {
        Alert(L"Metin eklenemedi veya kısmen eklendi. Hedef alanı kontrol edin.\nText insertion failed or was partial. Check the target field.");
        return 0;
    }
    if (message==WM_SERVER_ERROR) { Alert(L"Yerel sunucu durdu. / The local server stopped."); DestroyWindow(window); return 0; }
    if (message==WM_DESTROY) { SetEvent(stop_event); PostQuitMessage(0); return 0; }
    return DefWindowProcW(window,message,param,detail);
}
int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR command, int show) {
    (void)previous; (void)command; (void)show;
    int result=1;
    HANDLE thread=NULL, single=NULL;
    HHOOK hook=NULL;
    BOOL winsock=FALSE, tray=FALSE, registered=FALSE;
    WSADATA wsa;
    Vault initial={0};
    wchar_t path[MAX_PATH];
    BYTE random[32];
    WNDCLASSW wc={0};
    /* No elevation: input injection into elevated programs is intentionally unsupported. */
    single=CreateMutexW(NULL,FALSE,L"Local\\BeeExpander.Security.v1");
    if (!single || GetLastError()==ERROR_ALREADY_EXISTS) goto cleanup;
    current_lang=PRIMARYLANGID(GetUserDefaultUILanguage())==LANG_TURKISH ? 0 : 1;
    if (!InitPaths(path)) { Alert(L"Kasa yolu okunamadı. / Could not initialize the vault location."); goto cleanup; }
    VaultResult loaded=LoadVaultFromFile(path,&initial);
    if (loaded==VAULT_LEGACY) {
        int choice=MessageBoxW(NULL,
            L"Eski şifrelenmemiş kasa bulundu. DPAPI ile şifrelensin mi?\nAçık metin .legacy.bak yedeği korunacak. Doğrulamadan sonra yedeği güvenli biçimde kaldırın.\n\n"
            L"A legacy plaintext vault was found. Encrypt it with DPAPI now?\nA plaintext .legacy.bak backup will be retained. Remove it securely after verification.\n"
            L"Protection is tied to this Windows user. Cross-device copying is not a supported migration method.",
            L"Bee Expander",MB_YESNO|MB_DEFBUTTON2|MB_ICONWARNING);
        if (choice!=IDYES) goto cleanup;
        if (!MigrateLegacyVault(path,&initial)) { Alert(L"Taşıma başarısız; kaynak/yedek korundu. / Migration failed; source/backup preserved."); goto cleanup; }
    } else if (loaded!=VAULT_OK && loaded!=VAULT_MISSING) {
        Alert(L"Kasa okunamadı veya doğrulanamadı. Dosya değiştirilmedi.\nThe vault could not be read or validated. The file was not changed."); goto cleanup;
    }
    if (!StateInit(&app,path,&initial)) goto cleanup;
    SecureZeroMemory(&initial,sizeof(initial));
    if (BCryptGenRandom(NULL,random,sizeof(random),BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0) goto cleanup;
    for (size_t i=0; i<sizeof(random); ++i) snprintf(csrf+2u*i,3,"%02x",(unsigned)random[i]);
    SecureZeroMemory(random,sizeof(random));
    stop_event=CreateEventW(NULL,TRUE,FALSE,NULL);
    if (!stop_event || WSAStartup(MAKEWORD(2,2),&wsa)!=0) goto cleanup;
    winsock=TRUE;
    if (!StartListener()) { Alert(L"127.0.0.1:7200 açılamadı. / Could not bind 127.0.0.1:7200."); goto cleanup; }
    wc.lpfnWndProc=WindowProc; wc.hInstance=instance; wc.lpszClassName=L"BeeExpanderTrayWindow";
    if (!RegisterClassW(&wc)) goto cleanup;
    registered=TRUE;
    app_window=CreateWindowW(wc.lpszClassName,L"Bee Expander",0,0,0,0,0,NULL,NULL,instance,NULL);
    if (!app_window) goto cleanup;
    nid.cbSize=sizeof(nid); nid.hWnd=app_window; nid.uID=1; nid.uFlags=NIF_ICON|NIF_MESSAGE|NIF_TIP;
    nid.uCallbackMessage=WM_TRAYICON; nid.hIcon=LoadIconW(NULL,IDI_APPLICATION);
    memcpy(nid.szTip,L"Bee Expander (127.0.0.1:7200)",sizeof(L"Bee Expander (127.0.0.1:7200)"));
    if (!nid.hIcon || !Shell_NotifyIconW(NIM_ADD,&nid)) goto cleanup;
    tray=TRUE;
    hook=SetWindowsHookExW(WH_KEYBOARD_LL,LowLevelKeyboardProc,instance,0);
    if (!hook) { Alert(L"Klavye kancası kurulamadı. / Could not install the keyboard hook."); goto cleanup; }
    thread=CreateThread(NULL,0,HttpServerThread,NULL,0,NULL);
    if (!thread) goto cleanup;
    MSG message;
    BOOL got;
    while ((got=GetMessageW(&message,NULL,0,0))>0) { TranslateMessage(&message); DispatchMessageW(&message); }
    result=got==0 ? 0 : 1;
cleanup:
    if (stop_event) SetEvent(stop_event);
    if (hook) UnhookWindowsHookEx(hook);
    if (thread) { WaitForSingleObject(thread,INFINITE); CloseHandle(thread); }
    if (listener!=INVALID_SOCKET) { closesocket(listener); listener=INVALID_SOCKET; }
    if (winsock) WSACleanup();
    if (tray) Shell_NotifyIconW(NIM_DELETE,&nid);
    if (app_window && IsWindow(app_window)) DestroyWindow(app_window);
    if (registered) UnregisterClassW(wc.lpszClassName,instance);
    if (stop_event) { CloseHandle(stop_event); stop_event=NULL; }
    if (single) CloseHandle(single);
    SecureZeroMemory(&initial,sizeof(initial)); SecureZeroMemory(&app.vault,sizeof(app.vault));
    SecureZeroMemory(key_buffer,sizeof(key_buffer)); SecureZeroMemory(csrf,sizeof(csrf)); SecureZeroMemory(random,sizeof(random));
    return result;
}
