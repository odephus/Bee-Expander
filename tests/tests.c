/* Compile the real application handlers into this console test executable.
   WinMain is linked but never called: no hooks, tray UI, user vault, or registry writes. */
#include "../main.c"
#include <wincrypt.h>

static unsigned checks;
static wchar_t test_root[MAX_PATH], fixture[MAX_PATH];
#define CHECK(expr) do { ++checks; if (!(expr)) { fprintf(stderr,"FAIL line %d: %s (error %lu)\n",__LINE__,#expr,(unsigned long)GetLastError()); exit(1); } } while (0)

static void FixturePath(wchar_t *out, const wchar_t *name) {
    CHECK(swprintf(out,MAX_PATH,L"%ls\\%ls",test_root,name)>0);
}
static void WriteBytes(const wchar_t *path, const BYTE *bytes, DWORD length) {
    CHECK(!wcsncmp(path,test_root,wcslen(test_root)));
    HANDLE file=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    DWORD written=0;
    CHECK(file!=INVALID_HANDLE_VALUE);
    CHECK(WriteFile(file,bytes,length,&written,NULL) && written==length);
    CHECK(CloseHandle(file));
}
static BYTE *ReadBytes(const wchar_t *path, DWORD *length) {
    HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    CHECK(file!=INVALID_HANDLE_VALUE);
    *length=GetFileSize(file,NULL);
    CHECK(*length!=INVALID_FILE_SIZE && *length<VAULT_MAX_FILE);
    BYTE *bytes=(BYTE *)calloc(*length+1u,1);
    CHECK(bytes!=NULL);
    DWORD read=0;
    CHECK(ReadFile(file,bytes,*length,&read,NULL) && read==*length);
    CHECK(CloseHandle(file));
    return bytes;
}
static void FillVault(Vault *vault, uint32_t count) {
    SecureZeroMemory(vault,sizeof(*vault)); vault->count=count;
    for (uint32_t i=0; i<count && i<MAX_VAULT_ITEMS; ++i) {
        CHECK(snprintf(vault->items[i].tag,TAG_CAP,"..fixture%lu..",(unsigned long)i)>0);
        /* Synthetic values generated only for tests; never production defaults. */
        for (size_t j=0; j<12u; ++j) vault->items[i].password[j]=(wchar_t)(L'A'+(i+(uint32_t)j)%26u);
        vault->items[i].password[12]=0x015f; /* Turkish */
        vault->items[i].password[13]=0xd83d; vault->items[i].password[14]=0xde00;
    }
}
static void TestVault(void) {
    Vault in={0}, out={0};
    FillVault(&in,2);
    CHECK(SaveVaultToFile(fixture,&in,TRUE));
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_OK);
    CHECK(!memcmp(&in,&out,sizeof(in)));
    DWORD length=0;
    BYTE *bytes=ReadBytes(fixture,&length);
    CHECK(length>16u && !memcmp(bytes,"BEEVLT\r\n",8));
    /* The serialized UTF-16 test secret must not be present in the ciphertext file. */
    for (DWORD i=0; i+30u<=length; ++i) CHECK(memcmp(bytes+i,in.items[0].password,30)!=0);
    CHECK(!SaveVaultToFile(fixture,&in,TRUE));
    FillVault(&in,0);
    CHECK(SaveVaultToFile(fixture,&in,FALSE));
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_OK && out.count==0);
    FillVault(&in,MAX_VAULT_ITEMS);
    memset(in.items[0].tag,'t',TAG_CAP-1u); in.items[0].tag[TAG_CAP-1u]=0;
    for (size_t i=0; i<PASSWORD_CAP-1u; ++i) in.items[0].password[i]=(wchar_t)(L'A'+i%26u);
    in.items[0].password[PASSWORD_CAP-1u]=0;
    CHECK(SaveVaultToFile(fixture,&in,FALSE));
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_OK && !memcmp(&in,&out,sizeof(in)));
    in.count=MAX_VAULT_ITEMS+1u;
    CHECK(!SaveVaultToFile(fixture,&in,FALSE));
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_OK && out.count==MAX_VAULT_ITEMS);
    in.count=MAX_VAULT_ITEMS;
    memset(in.items[0].tag,'x',TAG_CAP);
    CHECK(!SaveVaultToFile(fixture,&in,FALSE));
    FillVault(&in,1);
    for (size_t i=0; i<PASSWORD_CAP; ++i) in.items[0].password[i]=L'x';
    CHECK(!SaveVaultToFile(fixture,&in,FALSE));
    FillVault(&in,1); in.items[0].password[0]=0xd800; in.items[0].password[1]=0;
    CHECK(!SaveVaultToFile(fixture,&in,FALSE));
    FillVault(&in,1); memcpy(in.items[0].tag,"\xff",1);
    CHECK(!SaveVaultToFile(fixture,&in,FALSE));
    /* Repeated failures must leave caller state untouched. */
    FillVault(&out,1); Vault sentinel=out;
    WriteBytes(fixture,bytes,0);
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_INVALID && !memcmp(&out,&sentinel,sizeof(out)));
    WriteBytes(fixture,bytes,15);
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_INVALID);
    WriteBytes(fixture,bytes,length-1u);
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_INVALID);
    bytes[0]^=1; WriteBytes(fixture,bytes,length);
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_INVALID); bytes[0]^=1;
    bytes[8]=2; WriteBytes(fixture,bytes,length);
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_INVALID); bytes[8]=1;
    bytes[12]^=1; WriteBytes(fixture,bytes,length);
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_INVALID); bytes[12]^=1;
    bytes[length-1u]^=0x80; WriteBytes(fixture,bytes,length);
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_INVALID);
    free(bytes);
    BYTE excessive[4]={51,0,0,0};
    WriteBytes(fixture,excessive,sizeof(excessive));
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_INVALID);
    /* A DPAPI-authenticated payload still needs record-count validation. */
    DATA_BLOB input={sizeof(excessive),excessive}, encrypted={0};
    CHECK(CryptProtectData(&input,NULL,NULL,NULL,NULL,CRYPTPROTECT_UI_FORBIDDEN,&encrypted));
    BYTE *wrapped=(BYTE *)calloc(16u+encrypted.cbData,1); CHECK(wrapped!=NULL);
    memcpy(wrapped,"BEEVLT\r\n",8); wrapped[8]=1;
    for (unsigned i=0; i<4; ++i) wrapped[12u+i]=(BYTE)(encrypted.cbData>>(8u*i));
    memcpy(wrapped+16,encrypted.pbData,encrypted.cbData);
    WriteBytes(fixture,wrapped,16u+encrypted.cbData);
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_INVALID);
    LocalFree(encrypted.pbData); free(wrapped);
    BYTE *huge=(BYTE *)calloc(VAULT_MAX_FILE+1u,1); CHECK(huge!=NULL);
    WriteBytes(fixture,huge,VAULT_MAX_FILE+1u); free(huge);
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_INVALID);
    SecureZeroMemory(&in,sizeof(in)); SecureZeroMemory(&out,sizeof(out)); SecureZeroMemory(&sentinel,sizeof(sentinel));
    puts("PASS vault round trips, limits, invalid records, truncation, headers, ciphertext corruption");
}
static void TestLegacyAndFailure(void) {
    Vault in={0}, out={0}; FillVault(&in,2);
    _Static_assert(sizeof(VaultItem)==288u,"Legacy Windows record size"); /* Original Windows struct layout. */
    DWORD length=4u+in.count*(DWORD)sizeof(VaultItem);
    BYTE *legacy=(BYTE *)calloc(length,1); CHECK(legacy!=NULL);
    memcpy(legacy,&in.count,4); memcpy(legacy+4,in.items,length-4u);
    WriteBytes(fixture,legacy,length);
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_LEGACY && out.count==0);
    wchar_t backup[MAX_PATH];
    CHECK(swprintf(backup,MAX_PATH,L"%ls.legacy.bak",fixture)>0);
    WriteBytes(backup,legacy,length);
    CHECK(!MigrateLegacyVault(fixture,&out)); /* Existing backup is never overwritten. */
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_LEGACY);
    CHECK(DeleteFileW(backup));
    CHECK(MigrateLegacyVault(fixture,&out) && !memcmp(&in,&out,sizeof(in)));
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_OK && !memcmp(&in,&out,sizeof(in)));
    DWORD saved_length;
    BYTE *saved=ReadBytes(backup,&saved_length);
    CHECK(saved_length==length && !memcmp(legacy,saved,length));
    SecureZeroMemory(legacy,length); free(legacy); SecureZeroMemory(saved,saved_length); free(saved);
    /* Deny delete/write sharing: atomic replacement must fail without changing the vault. */
    HANDLE guard=CreateFileW(fixture,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    CHECK(guard!=INVALID_HANDLE_VALUE);
    Vault changed=in; changed.items[0].password[0]=L'Z';
    CHECK(!SaveVaultToFile(fixture,&changed,FALSE));
    CHECK(CloseHandle(guard));
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_OK && !memcmp(&out,&in,sizeof(in)));
    CHECK(SaveVaultToFile(fixture,&changed,FALSE));
    CHECK(LoadVaultFromFile(fixture,&out)==VAULT_OK && !memcmp(&out,&changed,sizeof(out)));
    wchar_t missing[MAX_PATH]; FixturePath(missing,L"missing\\vault.dat");
    CHECK(!SaveVaultToFile(missing,&in,FALSE));
    wchar_t pattern[MAX_PATH]; FixturePath(pattern,L"*.tmp");
    WIN32_FIND_DATAW found; HANDLE search=FindFirstFileW(pattern,&found);
    CHECK(search==INVALID_HANDLE_VALUE);
    CHECK(DeleteFileW(backup));
    SecureZeroMemory(&in,sizeof(in)); SecureZeroMemory(&out,sizeof(out)); SecureZeroMemory(&changed,sizeof(changed));
    puts("PASS explicit legacy migration, backup preservation, failed replacement and recovery");
}
static int Header(const char *s) {
    HttpRequest request;
    return ParseHeader(s,strlen(s),&request);
}
static void TestParser(void) {
    char result[32];
    CHECK(UrlDecode("a%2Bb+c",7,result,sizeof(result)) && !strcmp(result,"a+b c"));
    CHECK(!UrlDecode("%",1,result,sizeof(result)));
    CHECK(!UrlDecode("%0",2,result,sizeof(result)));
    CHECK(!UrlDecode("%GG",3,result,sizeof(result)));
    CHECK(!UrlDecode("%00",3,result,sizeof(result)));
    CHECK(!UrlDecode("%0a",3,result,sizeof(result)));
    CHECK(!UrlDecode("abcd",4,result,4));
    CHECK(UrlDecode("abc",3,result,4) && !strcmp(result,"abc"));
    CHECK(!ValidForm("tag=a&tag=b",strlen("tag=a&tag=b")));
    CHECK(!ValidForm("tag=a&%74ag=b",strlen("tag=a&%74ag=b")));
    CHECK(!ValidForm("tag=%GG",7));
    CHECK(!ValidForm("tag=a&",6));
    CHECK(ValidForm("pass=a%26b%3Dc&tag=x",20));
    CHECK(FormValue("pass=a%26b%3Dc&tag=x",20,"pass",result,sizeof(result)) && !strcmp(result,"a&b=c"));
    CHECK(HtmlEscape("<>&\"'",result,sizeof(result)) && !strcmp(result,"&lt;&gt;&amp;&quot;&#39;"));
    CHECK(!HtmlEscape("<",result,4));
    CHECK(Header("GET / HTTP/1.1\r\nHost: " LOCAL_HOST "\r\n\r\n")==1);
    CHECK(Header("GET / HTTP/1.1\r\nHost: attacker.example\r\n\r\n")==-1);
    CHECK(Header("GET / HTTP/1.1\r\nHost: " LOCAL_HOST "\r\nHost: " LOCAL_HOST "\r\n\r\n")==-1);
    CHECK(Header("GET / HTTP/1.1\r\nHost: " LOCAL_HOST "\r\nOrigin: https://attacker.example\r\n\r\n")==-1);
    CHECK(Header("GET / HTTP/1.1\r\nHost: " LOCAL_HOST "\r\nSec-Fetch-Site: cross-site\r\n\r\n")==-1);
    CHECK(Header("GET / HTTP/1.1\r\nHost: " LOCAL_HOST "\r\nTransfer-Encoding: chunked\r\n\r\n")==-1);
    CHECK(Header("GET / HTTP/1.1\r\nHost: " LOCAL_HOST "\r\nContent-Length: 1\r\n\r\n")==-1);
    CHECK(Header("GET / HTTP/1.1\r\nHost: " LOCAL_HOST "\r\n")==0);
    CHECK(Header("POST /add HTTP/1.1\r\nHost: " LOCAL_HOST "\r\nContent-Length: 0\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n")==-1);
    CHECK(Header("POST /add HTTP/1.1\r\nHost: " LOCAL_HOST "\r\nOrigin: " LOCAL_ORIGIN "\r\nContent-Length: 4097\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n")==-1);
    CHECK(Header("POST /add HTTP/1.1\r\nHost: " LOCAL_HOST "\r\nOrigin: " LOCAL_ORIGIN "\r\nContent-Length: 18446744073709551616\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n")==-1);
    CHECK(Header("GET /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\nHost: " LOCAL_HOST "\r\n\r\n")==-1);
    char huge[HTTP_HEADER_MAX]; memset(huge,'a',sizeof(huge)); HttpRequest request;
    CHECK(ParseHeader(huge,sizeof(huge),&request)==-1);
    char nul[]="GET / HTTP/1.1\r\nHost: " LOCAL_HOST "\r\nX: z\r\n\r\n";
    nul[4]=0; CHECK(ParseHeader(nul,sizeof(nul)-1u,&request)==-1);
    /* Deterministic malformed-input corpus for bounds/runtime instrumentation. */
    uint32_t random=0x12345678u;
    for (size_t i=0; i<10000u; ++i) {
        size_t n=i%sizeof(huge);
        for (size_t j=0; j<n; ++j) { random=random*1664525u+1013904223u; huge[j]=(char)(random>>24); }
        (void)ParseHeader(huge,n,&request);
        (void)UrlDecode(huge,n,result,sizeof(result));
    }
    puts("PASS bounded URL/form/HTTP parsing, origin/host policy, escaping and malformed corpus");
}
static volatile LONG thread_failure, reader_stop, reader_matches;
static DWORD WINAPI ReadState(LPVOID unused) {
    (void)unused;
    while (!InterlockedCompareExchange(&reader_stop,0,0)) {
        wchar_t password[PASSWORD_CAP]={0}; size_t length=0;
        if (StateMatch(&app,L"..fixture0..",password,&length)) {
            if (length!=12u || (password[0]!=L'A' && password[0]!=L'Z')) InterlockedExchange(&thread_failure,1);
            InterlockedIncrement(&reader_matches);
        }
        SecureZeroMemory(password,sizeof(password));
        SwitchToThread();
    }
    return 0;
}
static void TestState(void) {
    Vault in={0}, out={0}; FillVault(&in,1);
    CHECK(SaveVaultToFile(fixture,&in,FALSE)); CHECK(StateInit(&app,fixture,&in));
    HANDLE readers[4];
    reader_stop=0; thread_failure=0; reader_matches=0;
    for (size_t i=0; i<4u; ++i) { readers[i]=CreateThread(NULL,0,ReadState,NULL,0,NULL); CHECK(readers[i]!=NULL); }
    uint32_t revision;
    for (unsigned i=0; i<20u; ++i) {
        StateSnapshot(&app,&out,&revision);
        out.items[0].password[0]=(i%2u) ? L'A' : L'Z';
        CHECK(StateCommit(&app,&out,revision));
        CHECK(!StateCommit(&app,&out,revision));
        Sleep(1);
    }
    InterlockedExchange(&reader_stop,1);
    CHECK(WaitForMultipleObjects(4,readers,TRUE,10000)==WAIT_OBJECT_0);
    for (size_t i=0; i<4u; ++i) CHECK(CloseHandle(readers[i]));
    CHECK(!thread_failure && reader_matches>0);
    StateSnapshot(&app,&out,&revision);
    HANDLE guard=CreateFileW(fixture,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    CHECK(guard!=INVALID_HANDLE_VALUE);
    in=out; in.count=0;
    CHECK(!StateCommit(&app,&in,revision)); CHECK(CloseHandle(guard));
    StateSnapshot(&app,&in,&revision);
    CHECK(!memcmp(&in,&out,sizeof(in)));
    SecureZeroMemory(&in,sizeof(in)); SecureZeroMemory(&out,sizeof(out));
    FillVault(&in,1);
    memcpy(in.items[0].tag,"..\xc5\x9fifre..",sizeof("..\xc5\x9fifre.."));
    CHECK(StateInit(&app,fixture,&in));
    wchar_t matched[PASSWORD_CAP]={0}; size_t trigger=0;
    CHECK(StateMatch(&app,L"prefix..şifre..",matched,&trigger) && trigger==9u);
    CHECK(!StateMatch(&app,L"..şifre..suffix",matched,&trigger));
    CHECK(!DoReplaceText(0,L""));
    CHECK(!DoReplaceText(TAG_CAP,L""));
    for (size_t i=0; i<PASSWORD_CAP; ++i) matched[i]=L'x';
    CHECK(!DoReplaceText(1,matched));
    SecureZeroMemory(matched,sizeof(matched)); SecureZeroMemory(&in,sizeof(in));
    puts("PASS concurrent vault readers/writers, stale revisions, failed-save memory rollback, Unicode matching");
}
static void TestLocationAndRendering(void) {
    Vault in={0}, loaded={0}; FillVault(&in,MAX_VAULT_ITEMS);
    CHECK(SaveVaultToFile(fixture,&in,FALSE)); CHECK(StateInit(&app,fixture,&in));
    memcpy(vault_dir,test_root,(wcslen(test_root)+1u)*sizeof(wchar_t));
    FixturePath(config_path,L"config.txt");
    char *page=(char *)calloc(PAGE_CAP,1); CHECK(page!=NULL);
    current_lang=0; CHECK(RenderPage(page) && strstr(page,"Kasaya Ekle"));
    current_lang=1; CHECK(RenderPage(page) && strstr(page,"Add to Vault"));
    char tag[TAG_CAP]; CHECK(snprintf(tag,sizeof(tag),"..fixture%u..",MAX_VAULT_ITEMS-1u)>0);
    CHECK(strstr(page,tag)!=NULL); free(page);
    wchar_t moved[MAX_PATH], moved_file[MAX_PATH], failed[MAX_PATH], failed_file[MAX_PATH];
    FixturePath(moved,L"moved"); FixturePath(failed,L"failed");
    CHECK(JoinPath(moved_file,moved,L"vault.dat")); CHECK(JoinPath(failed_file,failed,L"vault.dat"));
    char utf8[MAX_PATH*4u];
    CHECK(WideCharToMultiByte(CP_UTF8,0,moved,-1,utf8,sizeof(utf8),NULL,NULL)>0);
    CHECK(CreateDirectoryW(moved,NULL)); CHECK(SaveVaultToFile(moved_file,&in,TRUE));
    CHECK(!MoveVault(utf8) && !wcscmp(app.path,fixture)); /* Do not overwrite destination. */
    CHECK(DeleteFileW(moved_file));
    CHECK(MoveVault(utf8) && !wcscmp(app.path,moved_file));
    CHECK(LoadVaultFromFile(fixture,&loaded)==VAULT_OK && loaded.count==MAX_VAULT_ITEMS);
    CHECK(LoadVaultFromFile(moved_file,&loaded)==VAULT_OK && !memcmp(&in,&loaded,sizeof(in)));
    /* Config replacement failure: old active path must survive, new encrypted copy is retained. */
    HANDLE guard=CreateFileW(config_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    CHECK(guard!=INVALID_HANDLE_VALUE);
    CHECK(WideCharToMultiByte(CP_UTF8,0,failed,-1,utf8,sizeof(utf8),NULL,NULL)>0);
    CHECK(!MoveVault(utf8) && !wcscmp(app.path,moved_file));
    CHECK(CloseHandle(guard));
    CHECK(LoadVaultFromFile(failed_file,&loaded)==VAULT_OK && !memcmp(&in,&loaded,sizeof(in)));
    CHECK(!MoveVault("relative-path"));
    CHECK(!MoveVault("\\\\server\\share"));
    wchar_t too_long[MAX_PATH+1u];
    for (size_t i=0; i<MAX_PATH; ++i) too_long[i]=L'a';
    too_long[MAX_PATH]=0;
    AppState invalid;
    CHECK(!StateInit(&invalid,too_long,&in));
    CHECK(DeleteFileW(moved_file)); CHECK(DeleteFileW(failed_file)); CHECK(DeleteFileW(config_path));
    CHECK(RemoveDirectoryW(moved)); CHECK(RemoveDirectoryW(failed));
    CHECK(StateInit(&app,fixture,&in));
    SecureZeroMemory(&in,sizeof(in)); SecureZeroMemory(&loaded,sizeof(loaded));
    puts("PASS maximum bilingual page, location moves, destination collision and config-write rollback");
}


static unsigned short test_port;
static char *Exchange(const char *request, BOOL fragmented) {
    SOCKET client=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); CHECK(client!=INVALID_SOCKET);
    struct sockaddr_in address={0};
    address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(test_port);
    DWORD timeout=7000;
    CHECK(setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,(const char *)&timeout,sizeof(timeout))==0);
    CHECK(connect(client,(const struct sockaddr *)&address,sizeof(address))==0);
    size_t length=strlen(request);
    if (fragmented) {
        for (size_t i=0; i<length; i+=7u) {
            size_t n=length-i<7u ? length-i : 7u;
            CHECK(SendAll(client,request+i,n)); Sleep(1);
        }
    } else CHECK(SendAll(client,request,length));
    CHECK(shutdown(client,SD_SEND)==0);
    char *response=(char *)calloc(PAGE_CAP+2048u,1); CHECK(response!=NULL);
    size_t used=0;
    for (;;) {
        int n=recv(client,response+used,(int)(PAGE_CAP+2047u-used),0);
        CHECK(n!=SOCKET_ERROR);
        if (!n) break;
        used+=(size_t)n; CHECK(used<PAGE_CAP+2047u);
    }
    CHECK(closesocket(client)==0);
    return response;
}
static void ExpectRequest(const char *request, int status, BOOL fragment) {
    char *response=Exchange(request,fragment), prefix[32];
    CHECK(snprintf(prefix,sizeof(prefix),"HTTP/1.1 %d ",status)>0);
    CHECK(!strncmp(response,prefix,strlen(prefix)));
    free(response);
}
static void Post(const char *path, const char *body, int status, BOOL fragment) {
    char request[HTTP_REQUEST_MAX+1u];
    int n=snprintf(request,sizeof(request),"POST %s HTTP/1.1\r\nHost: " LOCAL_HOST "\r\nOrigin: " LOCAL_ORIGIN
        "\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %lu\r\n\r\n%s",path,(unsigned long)strlen(body),body);
    CHECK(n>0 && (size_t)n<sizeof(request)); ExpectRequest(request,status,fragment);
    SecureZeroMemory(request,sizeof(request));
}
static void TestServer(void) {
    Vault in={0}; FillVault(&in,1); CHECK(StateInit(&app,fixture,&in)); CHECK(SaveVaultToFile(fixture,&in,FALSE));
    BYTE random[32]; CHECK(BCryptGenRandom(NULL,random,sizeof(random),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0);
    for (size_t i=0; i<sizeof(random); ++i) CHECK(snprintf(csrf+2u*i,3,"%02x",(unsigned)random[i])==2);
    WSADATA data; CHECK(WSAStartup(MAKEWORD(2,2),&data)==0);
    listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); CHECK(listener!=INVALID_SOCKET);
    struct sockaddr_in address={0}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    CHECK(bind(listener,(const struct sockaddr *)&address,sizeof(address))==0);
    int size=sizeof(address); CHECK(getsockname(listener,(struct sockaddr *)&address,&size)==0);
    test_port=ntohs(address.sin_port); CHECK(listen(listener,4)==0);
    stop_event=CreateEventW(NULL,TRUE,FALSE,NULL); CHECK(stop_event!=NULL);
    HANDLE server=CreateThread(NULL,0,HttpServerThread,NULL,0,NULL); CHECK(server!=NULL);
    char *response=Exchange("GET / HTTP/1.1\r\nHost: " LOCAL_HOST "\r\n\r\n",TRUE);
    CHECK(strstr(response,"HTTP/1.1 200 ") && strstr(response,"Cache-Control: no-store") && strstr(response,"frame-ancestors 'none'"));
    /* Native form navigation needs its same-origin Origin on POST /add. */
    CHECK(strstr(response,"\r\nReferrer-Policy: same-origin\r\n")!=NULL);
    char secret[PASSWORD_CAP*4u];
    CHECK(WideCharToMultiByte(CP_UTF8,0,in.items[0].password,-1,secret,sizeof(secret),NULL,NULL)>0);
    CHECK(!strstr(response,secret)); free(response); SecureZeroMemory(secret,sizeof(secret));
    ExpectRequest("GET /delete?index=0 HTTP/1.1\r\nHost: " LOCAL_HOST "\r\n\r\n",404,FALSE);
    ExpectRequest("GET / HTTP/1.1\r\nHost: attacker.example\r\n\r\n",400,FALSE);
    ExpectRequest("POST /add HTTP/1.1\r\nHost: " LOCAL_HOST "\r\nOrigin: https://attacker.example\r\nContent-Length: 0\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n",400,FALSE);
    ExpectRequest("POST /add HTTP/1.1\r\nHost: " LOCAL_HOST "\r\nOrigin: " LOCAL_ORIGIN "\r\nContent-Length: 10\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nx=1",400,FALSE);
    ExpectRequest("POST /add HTTP/1.1\r\nHost: " LOCAL_HOST "\r\nOrigin: null\r\nContent-Length: 0\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n",400,FALSE);
    Post("/add","tag=x&pass=x",403,FALSE);
    char body[HTTP_BODY_MAX+1u];
    CHECK(snprintf(body,sizeof(body),"csrf=%s&tag=%%3Cfixture%%3E&pass=%%41%%42%%43",csrf)>0);
    Post("/add",body,303,TRUE);
    Post("/add",body,400,FALSE); /* Duplicate trigger. */
    response=Exchange("GET / HTTP/1.1\r\nHost: " LOCAL_HOST "\r\n\r\n",FALSE);
    CHECK(strstr(response,"&lt;fixture&gt;") && !strstr(response,"<fixture>"));
    CHECK(!strstr(response,"ABC")); free(response);
    CHECK(snprintf(body,sizeof(body),"csrf=%s&index=0&revision=1",csrf)>0);
    Post("/delete",body,409,FALSE);
    CHECK(snprintf(body,sizeof(body),"csrf=%s&index=999999999999999&revision=2",csrf)>0);
    Post("/delete",body,400,FALSE);
    CHECK(snprintf(body,sizeof(body),"csrf=%s&index=1&revision=2",csrf)>0);
    Post("/delete",body,303,FALSE);
    CHECK(snprintf(body,sizeof(body),"csrf=%s&tag=%%FF&pass=%%41",csrf)>0);
    Post("/add",body,400,FALSE);
    CHECK(snprintf(body,sizeof(body),"csrf=%s&tag=a&pass=%%FF",csrf)>0);
    Post("/add",body,400,FALSE);
    CHECK(snprintf(body,sizeof(body),"csrf=%s&tag=abcdefghijklmnopqrstuvwxyz123456789&pass=%%41",csrf)>0);
    Post("/add",body,400,FALSE);
    CHECK(snprintf(body,sizeof(body),"csrf=%s&tag=x&pass=%%00",csrf)>0);
    Post("/add",body,403,FALSE);
    SOCKET slow=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); CHECK(slow!=INVALID_SOCKET);
    CHECK(connect(slow,(const struct sockaddr *)&address,sizeof(address))==0);
    CHECK(SendAll(slow,"GET / HTTP/1.1\r\n",16));
    Sleep(150);
    CHECK(SetEvent(stop_event));
    CHECK(WaitForSingleObject(server,2000)==WAIT_OBJECT_0);
    CHECK(closesocket(slow)==0);
    CHECK(WaitForSingleObject(server,7000)==WAIT_OBJECT_0); CHECK(CloseHandle(server));
    CHECK(closesocket(listener)==0); listener=INVALID_SOCKET;
    CHECK(CloseHandle(stop_event)); stop_event=NULL; CHECK(WSACleanup()==0);
    SecureZeroMemory(body,sizeof(body)); SecureZeroMemory(&in,sizeof(in)); SecureZeroMemory(csrf,sizeof(csrf));
    puts("PASS native HTTP integration: fragmented requests, incomplete bodies, CSRF, masking, escaping, mutations");
}
int main(void) {
    wchar_t base[MAX_PATH], name[40];
    BYTE nonce[4];
    CHECK(GetFullPathNameW(L"build",MAX_PATH,base,NULL)>0);
    CHECK(BCryptGenRandom(NULL,nonce,sizeof(nonce),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0);
    CHECK(swprintf(name,40,L"test-%02x%02x%02x%02x",nonce[0],nonce[1],nonce[2],nonce[3])>0);
    CHECK(swprintf(test_root,MAX_PATH,L"%ls\\%ls",base,name)>0);
    CHECK(CreateDirectoryW(test_root,NULL));
    FixturePath(fixture,L"fixture.dat");
    TestVault(); TestLegacyAndFailure(); TestParser(); TestState(); TestLocationAndRendering(); TestServer();
    CHECK(DeleteFileW(fixture)); CHECK(RemoveDirectoryW(test_root));
    SecureZeroMemory(&app.vault,sizeof(app.vault));
    printf("All %u checks passed.\n",checks);
    return 0;
}
