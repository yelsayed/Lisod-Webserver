#include "log.h"

FILE *log_file;

void init_log(const char *path) {
    FILE *l;

    if (!(l = fopen(path, "w"))) {
        fprintf(stderr, "Error opening log!\n");
        exit(EXIT_FAILURE);
    };

    setvbuf(l, NULL, _IOLBF, 0);

//    dup2(fileno(l),STDOUT_FILENO);
//    dup2(fileno(l),STDERR_FILENO);

    log_file = l;
}

void string_log(int out, const char *format, ...) {
    struct tm tm;
    time_t now;
    char date[100];
    va_list va;

    now = time(0);
    tm = *localtime(&now);
    strftime(date, 100, "%a, %d %b %Y %H:%M:%S %Z", &tm);

    if (out) {
        fprintf(log_file, "On %s -> ", date);
    } else {
        fprintf(log_file, "Error On %s -> ", date);
    }

    va_start(va, format);
    vfprintf(log_file, format, va);
}

void close_log() {
    fclose(log_file);
}