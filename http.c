#include "http.h"
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static int Hex(unsigned char c) {
    if (c >= '0' && c <= '9') return c-'0';
    if (c >= 'a' && c <= 'f') return c-'a'+10;
    if (c >= 'A' && c <= 'F') return c-'A'+10;
    return -1;
}
BOOL UrlDecode(const char *src, size_t length, char *dest, size_t capacity) {
    size_t used=0;
    if (!capacity) return FALSE;
    dest[0]=0;
    for (size_t i=0; i<length; ++i) {
        unsigned char c=(unsigned char)src[i];
        if (c == '%') {
            if (length-i < 3u) goto bad;
            int a=Hex((unsigned char)src[i+1]), b=Hex((unsigned char)src[i+2]);
            if (a<0 || b<0) goto bad;
            c=(unsigned char)(a*16+b); i+=2;
        } else if (c == '+') c=' ';
        if (!c || c<32u || c==127u || used+1u>=capacity) goto bad;
        dest[used++]=(char)c;
    }
    dest[used]=0;
    return TRUE;
bad:
    SecureZeroMemory(dest, capacity);
    return FALSE;
}
BOOL ValidForm(const char *body, size_t length) {
    char names[8][32]={{0}}, value[HTTP_BODY_MAX+1u];
    size_t offset=0, count=0;
    BOOL ok=FALSE;
    if (!length) goto done;
    while (offset<length) {
        size_t end=offset, eq=offset;
        while (end<length && body[end]!='&') ++end;
        while (eq<end && body[eq]!='=') ++eq;
        if (count==8u || eq==offset || eq==end) goto done;
        if (!UrlDecode(body+offset, eq-offset, names[count], sizeof(names[count])) ||
            !UrlDecode(body+eq+1u, end-eq-1u, value, sizeof(value))) goto done;
        for (size_t i=0; i<count; ++i) if (!strcmp(names[i], names[count])) goto done;
        ++count;
        if (end<length && end+1u==length) goto done;
        offset=end+1u;
    }
    ok=TRUE;
done:
    SecureZeroMemory(value, sizeof(value));
    return ok;
}
BOOL FormValue(const char *body, size_t length, const char *name, char *out, size_t capacity) {
    size_t offset=0;
    char key[32];
    if (!capacity) return FALSE;
    out[0]=0;
    while (offset<length) {
        size_t end=offset, eq=offset;
        while (end<length && body[end]!='&') ++end;
        while (eq<end && body[eq]!='=') ++eq;
        if (eq==end || !UrlDecode(body+offset, eq-offset, key, sizeof(key))) return FALSE;
        if (!strcmp(key,name)) return UrlDecode(body+eq+1u, end-eq-1u, out, capacity);
        offset=end+1u;
    }
    return FALSE;
}
BOOL HtmlEscape(const char *src, char *dest, size_t capacity) {
    size_t used=0;
    if (!capacity) return FALSE;
    for (; *src; ++src) {
        const char *replace=NULL;
        switch (*src) {
            case '&': replace="&amp;"; break;
            case '<': replace="&lt;"; break;
            case '>': replace="&gt;"; break;
            case '"': replace="&quot;"; break;
            case '\'': replace="&#39;"; break;
            default: break;
        }
        size_t n=replace ? strlen(replace) : 1u;
        if (n>=capacity-used) { dest[0]=0; return FALSE; }
        if (replace) memcpy(dest+used,replace,n); else dest[used]=*src;
        used+=n;
    }
    dest[used]=0; return TRUE;
}
static BOOL Decimal(const char *s, size_t *out) {
    size_t n=0;
    if (!*s) return FALSE;
    for (; *s; ++s) {
        if (*s<'0' || *s>'9' || n>(HTTP_BODY_MAX-(size_t)(*s-'0'))/10u) return FALSE;
        n=n*10u+(size_t)(*s-'0');
    }
    *out=n; return TRUE;
}
static BOOL HeaderName(const char *s) {
    for (; *s; ++s) {
        if ((*s>='A' && *s<='Z') || (*s>='a' && *s<='z') || (*s>='0' && *s<='9') ||
            strchr("!#$%&'*+-.^_~|", *s) || *s==96) continue;
        return FALSE;
    }
    return TRUE;
}
int ParseHeader(const char *data, size_t size, HttpRequest *out) {
    size_t end=0;
    char copy[HTTP_HEADER_MAX+1u];
    BOOL host=FALSE, origin=FALSE, length=FALSE, type=FALSE, fetch=FALSE;
    if (size>HTTP_REQUEST_MAX) return -1;
    for (size_t i=0; i+3u<size && i+3u<HTTP_HEADER_MAX; ++i)
        if (!memcmp(data+i,"\r\n\r\n",4)) { end=i+4u; break; }
    if (!end) return size>=HTTP_HEADER_MAX ? -1 : 0;
    for (size_t i=0; i<end; ++i) {
        unsigned char c=(unsigned char)data[i];
        if (!c || c==127u || (c<32u && c!='\r' && c!='\n' && c!='\t')) return -1;
        if (c=='\n' && (!i || data[i-1]!='\r')) return -1;
        if (c=='\r' && (i+1u>=end || data[i+1]!='\n')) return -1;
    }
    memcpy(copy,data,end); copy[end]=0;
    SecureZeroMemory(out,sizeof(*out));
    char *line=copy, *next=strstr(line,"\r\n");
    if (!next) return -1;
    *next=0;
    char *space=strchr(line,' ');
    if (!space) return -1;
    *space++=0;
    if (strcmp(line,"GET") && strcmp(line,"POST")) return -1;
    out->post=!strcmp(line,"POST");
    memcpy(out->method,line,strlen(line)+1u);
    char *version=strchr(space,' ');
    if (!version) return -1;
    *version++=0;
    if (strcmp(version,"HTTP/1.1") || *space!='/' || strlen(space)>=sizeof(out->path)) return -1;
    for (const char *p=space; *p; ++p) if ((unsigned char)*p<=32u || (unsigned char)*p>=127u) return -1;
    memcpy(out->path,space,strlen(space)+1u);
    line=next+2;
    while (*line) {
        next=strstr(line,"\r\n");
        if (!next) return -1;
        *next=0;
        if (!*line) break;
        char *colon=strchr(line,':');
        if (!colon || colon==line || line[0]==' ' || line[0]=='\t') return -1;
        *colon++=0;
        if (!HeaderName(line)) return -1;
        while (*colon==' ' || *colon=='\t') ++colon;
        char *tail=colon+strlen(colon);
        while (tail>colon && (tail[-1]==' ' || tail[-1]=='\t')) *--tail=0;
        if (!_stricmp(line,"Host")) {
            if (host || strcmp(colon,LOCAL_HOST)) return -1;
            host=TRUE;
        } else if (!_stricmp(line,"Origin")) {
            if (origin || strcmp(colon,LOCAL_ORIGIN)) return -1;
            origin=TRUE;
        } else if (!_stricmp(line,"Content-Length")) {
            if (length || !Decimal(colon,&out->body_length)) return -1;
            length=TRUE;
        } else if (!_stricmp(line,"Content-Type")) {
            if (type || _stricmp(colon,"application/x-www-form-urlencoded")) return -1;
            type=TRUE;
        } else if (!_stricmp(line,"Transfer-Encoding") || !_stricmp(line,"Expect")) return -1;
        else if (!_stricmp(line,"Sec-Fetch-Site")) {
            if (fetch || (strcmp(colon,"same-origin") && strcmp(colon,"none"))) return -1;
            fetch=TRUE;
        }
        line=next+2;
    }
    if (!host || (out->post && (!origin || !length || !type)) || (!out->post && out->body_length)) return -1;
    out->header_length=end;
    return 1;
}
BOOL ReadRequest(SOCKET client, HANDLE stop, char *buffer, HttpRequest *request) {
    size_t used=0, total=0;
    ULONGLONG deadline=GetTickCount64()+5000u;
    BOOL parsed=FALSE;
    while (GetTickCount64()<deadline && WaitForSingleObject(stop,0)==WAIT_TIMEOUT) {
        fd_set read_set; FD_ZERO(&read_set); FD_SET(client,&read_set);
        struct timeval wait={0,100000};
        int ready=select(0,&read_set,NULL,NULL,&wait);
        if (ready==SOCKET_ERROR) return FALSE;
        if (!ready) continue;
        int n=recv(client,buffer+used,(int)(HTTP_REQUEST_MAX-used),0);
        if (n<=0) return FALSE;
        used+=(size_t)n; buffer[used]=0;
        if (!parsed) {
            int result=ParseHeader(buffer,used,request);
            if (result<0) return FALSE;
            parsed=result==1;
            if (parsed) total=request->header_length+request->body_length;
        }
        if (parsed && used>=total) return used==total;
        if (used==HTTP_REQUEST_MAX) return FALSE;
    }
    return FALSE;
}
BOOL SendAll(SOCKET client, const char *data, size_t length) {
    if (length > INT_MAX) return FALSE;
    ULONGLONG deadline=GetTickCount64()+5000u;
    while (length && GetTickCount64()<deadline) {
        int sent=send(client,data,(int)length,0);
        if (sent<=0) return FALSE;
        data+=sent; length-=(size_t)sent;
    }
    return length==0;
}
BOOL SendResponse(SOCKET client, int status, const char *body) {
    char header[1024];
    const char *reason=status==200 ? "OK" : status==303 ? "See Other" : status==400 ? "Bad Request" :
        status==403 ? "Forbidden" : status==404 ? "Not Found" : status==409 ? "Conflict" : "Internal Server Error";
    int n=snprintf(header,sizeof(header),
        "HTTP/1.1 %d %s\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: %lu\r\n"
        "Connection: close\r\nCache-Control: no-store\r\nPragma: no-cache\r\n"
        "X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\n"
        "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'\r\n%s\r\n",
        status,reason,(unsigned long)strlen(body),status==303 ? "Location: /\r\n" : "");
    if (n<0 || (size_t)n>=sizeof(header)) return FALSE;
    return SendAll(client,header,(size_t)n) && SendAll(client,body,strlen(body));
}
