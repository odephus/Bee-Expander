#ifndef BEE_HTTP_H
#define BEE_HTTP_H
#include <winsock2.h>
#include <windows.h>
#include <stddef.h>
#define HTTP_HEADER_MAX 8192u
#define HTTP_BODY_MAX 4096u
#define HTTP_REQUEST_MAX (HTTP_HEADER_MAX + HTTP_BODY_MAX)
#define LOCAL_HOST "127.0.0.1:7200"
#define LOCAL_ORIGIN "http://" LOCAL_HOST
typedef struct {
    char method[5], path[32];
    size_t header_length, body_length;
    BOOL post;
} HttpRequest;
int ParseHeader(const char *data, size_t size, HttpRequest *out);
BOOL ReadRequest(SOCKET client, HANDLE stop, char *buffer, HttpRequest *request);
BOOL UrlDecode(const char *src, size_t length, char *dest, size_t capacity);
BOOL FormValue(const char *body, size_t length, const char *name, char *out, size_t capacity);
BOOL ValidForm(const char *body, size_t length);
BOOL HtmlEscape(const char *src, char *dest, size_t capacity);
BOOL SendAll(SOCKET client, const char *data, size_t length);
BOOL SendResponse(SOCKET client, int status, const char *body);
#endif
