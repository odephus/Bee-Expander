#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")

#define BUFFER_SIZE 64
#define PORT 7200
#define MAX_VAULT_ITEMS 50
#define WM_TRAYICON (WM_USER + 1)
#define IDM_OPEN_UI 1001
#define IDM_EXIT 1002
#define VAULT_DIR "C:\\Users\\alber"
#define VAULT_FILE "C:\\Users\\alber\\vault.dat"

typedef struct {
    char tag[32];
    wchar_t password[128];
} VaultItem;

VaultItem vault[MAX_VAULT_ITEMS];
int vault_count = 0;
int current_lang = 0;

char key_buffer[BUFFER_SIZE] = {0};
NOTIFYICONDATA nid;

BOOL IsUserAnAdminSelf() {
    BOOL b = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
        CheckTokenMembership(NULL, AdministratorsGroup, &b);
        FreeSid(AdministratorsGroup);
    }
    return b;
}

void RelaunchAsAdmin() {
    char szPath[MAX_PATH];
    GetModuleFileNameA(NULL, szPath, MAX_PATH);
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpVerb = "runas";
    sei.lpFile = szPath;
    sei.hwnd = NULL;
    sei.nShow = SW_NORMAL;
    if (ShellExecuteExA(&sei)) {
        ExitProcess(0);
    }
}

void DetectSystemLanguage() {
    LANGID langId = GetUserDefaultUILanguage();
    if (PRIMARYLANGID(langId) == LANG_TURKISH) {
        current_lang = 0;
    } else {
        current_lang = 1;
    }
}

void EnsureDirectoryExists() {
    CreateDirectoryA(VAULT_DIR, NULL);
}

void SaveVaultToFile() {
    EnsureDirectoryExists();
    FILE *f = fopen(VAULT_FILE, "wb");
    if (f) {
        fwrite(&vault_count, sizeof(int), 1, f);
        fwrite(vault, sizeof(VaultItem), vault_count, f);
        fclose(f);
    }
}

void LoadVaultFromFile() {
    EnsureDirectoryExists();
    FILE *f = fopen(VAULT_FILE, "rb");
    if (f) {
        if (fread(&vault_count, sizeof(int), 1, f) == 1) {
            fread(vault, sizeof(VaultItem), vault_count, f);
        }
        fclose(f);
    } else {
        strcpy(vault[0].tag, "..passwd..");
        mbstowcs(vault[0].password, "alperbabasictitasa72", 128);
        vault_count = 1;
        SaveVaultToFile();
    }
}

void UrlDecode(char* src, char* dest) {
    char a, b;
    while (*src) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2]))) {
            if (a >= '0' && a <= '9') a -= '0';
            else if (a >= 'a' && a <= 'f') a -= 'a' - 10;
            else if (a >= 'A' && a <= 'F') a -= 'A' - 10;

            if (b >= '0' && b <= '9') b -= '0';
            else if (b >= 'a' && b <= 'f') b -= 'a' - 10;
            else if (b >= 'A' && b <= 'F') b -= 'A' - 10;

            *dest++ = 16 * a + b;
            src += 3;
        } else if (*src == '+') {
            *dest++ = ' ';
            src++;
        } else {
            *dest++ = *src++;
        }
    }
    *dest = '\0';
}

void SendBackspace(int count) {
    INPUT inputs[2];
    memset(inputs, 0, sizeof(inputs));
    inputs[0].type = INPUT_KEYBOARD;
    inputs[0].ki.wVk = VK_BACK;
    inputs[1].type = INPUT_KEYBOARD;
    inputs[1].ki.wVk = VK_BACK;
    inputs[1].ki.dwFlags = KEYEVENTF_KEYUP;

    for (int i = 0; i < count; i++) {
        SendInput(2, inputs, sizeof(INPUT));
        Sleep(5);
    }
}

void DoReplaceText(int trigger_len, const wchar_t* new_text) {
    SendBackspace(trigger_len - 1);
    Sleep(20);

    if (OpenClipboard(NULL)) {
        EmptyClipboard();
        size_t size = (wcslen(new_text) + 1) * sizeof(wchar_t);
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, size);
        if (hMem) {
            memcpy(GlobalLock(hMem), new_text, size);
            GlobalUnlock(hMem);
            SetClipboardData(CF_UNICODETEXT, hMem);
        }
        CloseClipboard();

        INPUT inputs[4];
        memset(inputs, 0, sizeof(inputs));

        inputs[0].type = INPUT_KEYBOARD;
        inputs[0].ki.wVk = VK_CONTROL;

        inputs[1].type = INPUT_KEYBOARD;
        inputs[1].ki.wVk = 'V';

        inputs[2].type = INPUT_KEYBOARD;
        inputs[2].ki.wVk = 'V';
        inputs[2].ki.dwFlags = KEYEVENTF_KEYUP;

        inputs[3].type = INPUT_KEYBOARD;
        inputs[3].ki.wVk = VK_CONTROL;
        inputs[3].ki.dwFlags = KEYEVENTF_KEYUP;

        SendInput(4, inputs, sizeof(INPUT));
    }
}

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT *p = (KBDLLHOOKSTRUCT *)lParam;

        BYTE keyboardState[256];
        GetKeyboardState(keyboardState);

        keyboardState[VK_SHIFT] = (GetAsyncKeyState(VK_SHIFT) & 0x8000) ? 0x80 : 0;
        keyboardState[VK_LSHIFT] = (GetAsyncKeyState(VK_LSHIFT) & 0x8000) ? 0x80 : 0;
        keyboardState[VK_RSHIFT] = (GetAsyncKeyState(VK_RSHIFT) & 0x8000) ? 0x80 : 0;
        keyboardState[VK_CAPITAL] = (GetKeyState(VK_CAPITAL) & 0x0001) ? 0x01 : 0;

        HWND hwnd = GetForegroundWindow();
        DWORD threadId = GetWindowThreadProcessId(hwnd, NULL);
        HKL layout = GetKeyboardLayout(threadId);

        WCHAR unicodeChar[2] = {0};
        int result = ToUnicodeEx(p->vkCode, p->scanCode, keyboardState, unicodeChar, 2, 0, layout);

        if (result == 1) { 
            char c = (char)unicodeChar[0];

            size_t len = strlen(key_buffer);
            if (len >= BUFFER_SIZE - 1) {
                memmove(key_buffer, key_buffer + 1, BUFFER_SIZE - 2);
                key_buffer[BUFFER_SIZE - 2] = c;
                key_buffer[BUFFER_SIZE - 1] = '\0';
            } else {
                key_buffer[len] = c;
                key_buffer[len + 1] = '\0';
            }

            for (int i = 0; i < vault_count; i++) {
                if (strstr(key_buffer, vault[i].tag) != NULL) {
                    memset(key_buffer, 0, sizeof(key_buffer));
                    DoReplaceText((int)strlen(vault[i].tag), vault[i].password);
                    return 1;
                }
            }
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

DWORD WINAPI HttpServerThread(LPVOID lpParam) {
    WSADATA wsa;
    SOCKET server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    WSAStartup(MAKEWORD(2, 2), &wsa);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);

    while (1) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, (int*)&addrlen);
        if (new_socket != INVALID_SOCKET) {
            char buffer[2048] = {0};
            recv(new_socket, buffer, sizeof(buffer), 0);

            if (strstr(buffer, "GET /lang?set=en") != NULL) {
                current_lang = 1;
                char redirect[] = "HTTP/1.1 303 See Other\r\nLocation: /\r\n\r\n";
                send(new_socket, redirect, (int)strlen(redirect), 0);
                closesocket(new_socket);
                continue;
            } else if (strstr(buffer, "GET /lang?set=tr") != NULL) {
                current_lang = 0;
                char redirect[] = "HTTP/1.1 303 See Other\r\nLocation: /\r\n\r\n";
                send(new_socket, redirect, (int)strlen(redirect), 0);
                closesocket(new_socket);
                continue;
            }

            char* delete_pos = strstr(buffer, "GET /delete?index=");
            if (delete_pos != NULL) {
                int index_to_delete = -1;
                if (sscanf(delete_pos, "GET /delete?index=%d", &index_to_delete) == 1) {
                    if (index_to_delete >= 0 && index_to_delete < vault_count) {
                        for (int i = index_to_delete; i < vault_count - 1; i++) {
                            vault[i] = vault[i + 1];
                        }
                        vault_count--;
                        SaveVaultToFile();
                    }
                }
                char redirect[] = "HTTP/1.1 303 See Other\r\nLocation: /\r\n\r\n";
                send(new_socket, redirect, (int)strlen(redirect), 0);
                closesocket(new_socket);
                continue;
            }

            if (strncmp(buffer, "POST", 4) == 0) {
                char* body = strstr(buffer, "\r\n\r\n");
                if (body && vault_count < MAX_VAULT_ITEMS) {
                    body += 4;
                    char raw_tag[64] = {0}, raw_pass[256] = {0};
                    char decoded_tag[64] = {0}, decoded_pass[256] = {0};

                    if (sscanf(body, "tag=%[^&]&pass=%s", raw_tag, raw_pass) == 2) {
                        UrlDecode(raw_tag, decoded_tag);
                        UrlDecode(raw_pass, decoded_pass);

                        MultiByteToWideChar(CP_UTF8, 0, decoded_pass, -1, vault[vault_count].password, 128);

                        char formatted_tag[64] = {0};
                        if (strncmp(decoded_tag, "..", 2) == 0 && strcmp(decoded_tag + strlen(decoded_tag) - 2, "..") == 0) {
                            snprintf(formatted_tag, sizeof(formatted_tag), "%s", decoded_tag);
                        } else {
                            snprintf(formatted_tag, sizeof(formatted_tag), "..%s..", decoded_tag);
                        }

                        strncpy(vault[vault_count].tag, formatted_tag, sizeof(vault[vault_count].tag) - 1);
                        vault_count++;
                        SaveVaultToFile();
                    }
                }
                char redirect[] = "HTTP/1.1 303 See Other\r\nLocation: /\r\n\r\n";
                send(new_socket, redirect, (int)strlen(redirect), 0);
                closesocket(new_socket);
                continue;
            }

            const char* title = (current_lang == 0) ? "Password Expander Vault" : "Password Expander Vault";
            const char* add_title = (current_lang == 0) ? "Yeni Eklemeler" : "Add New Item";
            const char* ph_tag = (current_lang == 0) ? "Tag (Örn: passwdfb)" : "Tag (e.g. passwdfb)";
            const char* ph_pass = (current_lang == 0) ? "Şifre (Örn: gizli123)" : "Password (e.g. secret123)";
            const char* btn_text = (current_lang == 0) ? "Kasaya Ekle" : "Add to Vault";
            const char* th_tag = (current_lang == 0) ? "Tetikleyici Tag" : "Trigger Tag";
            const char* th_pass = (current_lang == 0) ? "Kayıtlı Şifre" : "Saved Password";
            const char* th_action = (current_lang == 0) ? "İşlem" : "Action";
            const char* btn_del = (current_lang == 0) ? "Sil" : "Delete";

            char html[2048];
            snprintf(html, sizeof(html),
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n"
                "<!DOCTYPE html><html><head><title>C-Vault Expander</title>"
                "<style>body{font-family:Segoe UI,sans-serif;background:#121212;color:#eee;padding:30px;max-width:650px;margin:auto;}"
                ".header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #333;padding-bottom:10px;}"
                "h2{color:#00ff88;margin:0;}"
                ".lang-btn{color:#00ff88;text-decoration:none;border:1px solid #00ff88;padding:4px 8px;border-radius:4px;font-size:12px;}"
                "form{background:#1e1e1e;padding:15px;border-radius:8px;margin:20px 0;}"
                "input,button{padding:10px;margin:5px 0;width:95%%;border-radius:4px;border:1px solid #333;background:#252525;color:#fff;}"
                "button{background:#00ff88;color:#000;font-weight:bold;cursor:pointer;width:100%%;}"
                "table{width:100%%;border-collapse:collapse;}th,td{border:1px solid #333;padding:10px;text-align:left;}"
                "th{background:#1e1e1e;color:#00ff88;}"
                ".btn-delete{background:#ff4444;color:#fff;text-decoration:none;padding:5px 10px;border-radius:4px;font-size:12px;font-weight:bold;display:inline-block;}</style></head><body>"
                "<div class='header'><h2>%s</h2><div><a class='lang-btn' href='/lang?set=tr'>TR</a> <a class='lang-btn' href='/lang?set=en'>EN</a></div></div>"
                "<form method='POST' action='/'>"
                "<h3>%s</h3>"
                "<input type='text' name='tag' placeholder='%s' required><br>"
                "<input type='text' name='pass' placeholder='%s' required><br><br>"
                "<button type='submit'>%s</button>"
                "</form>"
                "<table><tr><th>%s</th><th>%s</th><th style='width:60px;'>%s</th></tr>",
                title, add_title, ph_tag, ph_pass, btn_text, th_tag, th_pass, th_action);

            send(new_socket, html, (int)strlen(html), 0);

            for (int i = 0; i < vault_count; i++) {
                char pass_utf8[256] = {0};
                WideCharToMultiByte(CP_UTF8, 0, vault[i].password, -1, pass_utf8, sizeof(pass_utf8), NULL, NULL);

                char row[512];
                snprintf(row, sizeof(row), "<tr><td>%s</td><td>%s</td><td><a class='btn-delete' href='/delete?index=%d'>%s</a></td></tr>", vault[i].tag, pass_utf8, i, btn_del);
                send(new_socket, row, (int)strlen(row), 0);
            }

            char html_end[] = "</table></body></html>";
            send(new_socket, html_end, (int)strlen(html_end), 0);

            closesocket(new_socket);
        }
    }
    WSACleanup();
    return 0;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_TRAYICON) {
        if (lParam == WM_LBUTTONDBLCLK) {
            ShellExecuteA(NULL, "open", "http://127.0.0.1:7200", NULL, NULL, SW_SHOWNORMAL);
        } else if (lParam == WM_RBUTTONUP) {
            POINT pt;
            GetCursorPos(&pt);
            HMENU hMenu = CreatePopupMenu();
            
            const wchar_t* menu_open = (current_lang == 0) ? L"Arayüzü Aç" : L"Open Web UI";
            const wchar_t* menu_exit = (current_lang == 0) ? L"Çıkış" : L"Exit";

            AppendMenuW(hMenu, MF_STRING, IDM_OPEN_UI, menu_open);
            AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hMenu, MF_STRING, IDM_EXIT, menu_exit);

            SetForegroundWindow(hwnd);
            int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, NULL);
            DestroyMenu(hMenu);

            if (cmd == IDM_OPEN_UI) {
                ShellExecuteA(NULL, "open", "http://127.0.0.1:7200", NULL, NULL, SW_SHOWNORMAL);
            } else if (cmd == IDM_EXIT) {
                PostQuitMessage(0);
            }
        }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if (!IsUserAnAdminSelf()) {
        RelaunchAsAdmin();
        return 0;
    }

    setlocale(LC_ALL, "tr-TR.UTF8");

    DetectSystemLanguage();
    LoadVaultFromFile();

    CreateThread(NULL, 0, HttpServerThread, NULL, 0, NULL);

    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "TrayWindowClass";
    RegisterClass(&wc);

    HWND hwnd = CreateWindow("TrayWindowClass", "TrayWindow", 0, 0, 0, 0, 0, NULL, NULL, hInstance, NULL);

    memset(&nid, 0, sizeof(NOTIFYICONDATA));
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    strcpy(nid.szTip, "Password Expander (127.0.0.1:7200)");
    Shell_NotifyIcon(NIM_ADD, &nid);

    HHOOK hHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, 0);
    if (!hHook) {
        return 1;
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    Shell_NotifyIcon(NIM_DELETE, &nid);
    UnhookWindowsHookEx(hHook);
    return 0;
}