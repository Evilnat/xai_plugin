#ifndef _LOG_H
#define _LOG_H

#include <stdio.h>

void load_log_functions();
char *getlogpath();
void setlogpath(char *path);

static int (*vsh_sprintf)( char*, const char*,...);
static int (*vsh_swprintf)(wchar_t *, size_t, const wchar_t *,...);

int sprintf_(char *str, const char *format, int v1);
int sprintf_(char *str, const char *format, int v1, int v2);
int sprintf_(char *str, const char *format, int v1, int v2, int v3);
int sprintf_(char *str, const char *format, int v1, int v2, int v3, int v4);
int sprintf_(char *str, const char *format, int v1, int v2, int v3, int v4, int v5);
int sprintf_(char *str, const char *format, int v1, int v2, int v3, int v4, int v5, int v6);
int sprintf_(char *str, const char *format, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8);
int sprintf_(char *str, const char *format, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8, int v9, int v10, int v11, int v12, int v13, int v14, int v15, int v16);

int swprintf_(wchar_t *str, size_t size, const wchar_t *format);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2, int v3);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2, int v3, int v4);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2, int v3, int v4, int v5);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2, int v3, int v4, int v5, int v6);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2, int v3, int v4, int v5, int v6, int v7);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8, int v9);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8, int v9, int v10);

void log(wchar_t *buffer);
void log(char *buffer);
void log(char *format, char *param1);
void log(char *format, const char *param1);
void log(char *format, const wchar_t *param1);
void log(char *format, char param1);
void log(char *format, int param1);
void log(char *format, float param1);
void log(char *pluginname,char *view, const char *function);
void log_key(char *keyname,void *key);
void log_data(const void *buffer, int bufsize);

void log_function(char *pluginname,char *view, const char *function, char *format, int param1);
void log_function(char *pluginname,char *view, const char *function, char *format, const char*param1);

void notify(char *param);
void notify(const char *format, int param1);
void notify(const char *format, int param1, int param2);
void notify(const char *format, int param1, int param2, int param3);

#endif /* _LOG_H */
