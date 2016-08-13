#include "lisod.h"

struct server_state *server;

int close_socket(int sock) {
    if (close(sock)) {
        string_log(0, "Failed closing socket.\n");
        return 1;
    }
    return 0;
}

ssize_t swrite(char *buf, size_t len, int id, struct client_set *clients) {
    struct client *curr_client;

    curr_client = clients->client_arr[id];

    if (!curr_client->is_secure) {
        return send(curr_client->fd, buf, len, 0);
    } else {
        return SSL_write(curr_client->client_context, buf, len);
    }
}

ssize_t sread(int id, struct client_set *clients, char *buf, int len) {
    struct client *curr_client;

    curr_client = clients->client_arr[id];

    if (!curr_client->is_secure) {
        return recv(curr_client->fd, buf,
                    len, 0);
    } else {
        return SSL_read(curr_client->client_context, buf, len);
    }
}

void init_client_set(struct client_set *clients, struct server_state *state) {
    int i;
    server = state;
    if (server->secure_sock > server->sock) {
        clients->nfds = server->secure_sock;
    } else {
        clients->nfds = server->sock;
    }

    FD_ZERO(&(clients->read_set));
    FD_ZERO(&(clients->write_set));

    FD_SET(server->sock, &(clients->read_set));
    FD_SET(server->secure_sock, &(clients->read_set));

    for (i = 0; i < FD_SETSIZE; i++) {
        struct client *c = malloc(sizeof(struct client));
        c->fd = -42;
        clients->client_arr[i] = c;
    }
}

int add_cgi_client(struct client_set *clients, int stdout_pipe, int client_id) {
    int i;
    for (i = 0; i < FD_SETSIZE; i++) {
        if (clients->client_arr[i]->fd < 0) {

            FD_SET(stdout_pipe, &(clients->read_set));
            clients->client_arr[i]->fd = stdout_pipe;
            clients->client_arr[i]->read_buf = calloc(sizeof(char), BUF_SIZE);
            clients->client_arr[i]->buffer_size = BUF_SIZE;
            clients->client_arr[i]->read_buffer_marker = 0;
            clients->client_arr[i]->client_id = i;
            clients->client_arr[i]->cgi_client_id = client_id;
            clients->client_arr[i]->cgi_flag = 1;
            clients->client_arr[i]->is_secure = 0;

            if (stdout_pipe > clients->nfds) {
                clients->nfds = stdout_pipe;
            }

            return i;
        }
    }
    string_log(0, "Couldn't find space to put client.\n");
    return 0;
}

int add_client(int client_sock, struct client_set *clients,
               int secure, SSL *client_context) {
    int i;
    for (i = 0; i < FD_SETSIZE; i++) {
        if (clients->client_arr[i]->fd < 0) {

            // Add a new client to the set of clients
            clients->rfds -= 1;

            FD_SET(client_sock, &(clients->read_set));
            clients->client_arr[i]->fd = client_sock;
            clients->client_arr[i]->read_buf = calloc(sizeof(char), BUF_SIZE);
            clients->client_arr[i]->buffer_size = BUF_SIZE;
            clients->client_arr[i]->read_buffer_marker = 0;
            clients->client_arr[i]->is_alive = 1;
            clients->client_arr[i]->is_secure = secure;
            clients->client_arr[i]->client_context = client_context;
            clients->client_arr[i]->client_id = i;
            // Not cgi struct
            clients->client_arr[i]->cgi_flag = 0;
            clients->client_arr[i]->cgi_client_id = -42;

            if (client_sock > clients->nfds) {
                clients->nfds = client_sock;
            }
            return i;
        }
    }
    string_log(0, "Couldn't find space to put client.\n");
    return 0;
}

int close_client(int id, struct client_set *clients) {
    struct client *curr_client;
    int fd;

    curr_client = clients->client_arr[id];
    fd = curr_client->fd;

    FD_CLR(fd, &(clients->read_set));

    if (close_socket(fd)) {
        close_socket(server->secure_sock);
        close_socket(server->sock);
        string_log(0, "Error closing client socket.\n");
        return -1;
    }

    if (curr_client->is_secure) {
        SSL_shutdown(curr_client->client_context);
        SSL_free(curr_client->client_context);
    }

    curr_client->fd = -42;
    curr_client->buffer_size = BUF_SIZE;
    curr_client->read_buffer_marker = 0;

    return 1;
}

int process_clients(struct client_set *clients, struct server_state *state) {
    struct client *curr_client;
    int i, fd;

    for (i = 0; i <= clients->nfds && clients->rfds; i++) {
        curr_client = clients->client_arr[i];

        fd = curr_client->fd;

        if (fd == -42) {
            continue;
        }

        if (!(FD_ISSET(fd, &(clients->ready_set)))) {
            // Go to another client
            continue;
        }

        clients->rfds -= 1;

        string_log(1, "Reading request for client %d\n", fd);
        read_request(i, clients);
    }
    return 1;
}


void send_error(int id, struct client_set *clients, int error_type) {
    char head[MIN_BUF];
    char body[MIN_BUF];
    char date[MIN_BUF];
    char *error_name = "";
    char *error_message = "";

    time_t now = time(0);
    struct tm tm = *gmtime(&now);
    strftime(date, MIN_BUF, "%a, %d %b %Y %H:%M:%S %Z", &tm);

    if (error_type == 505) {
        error_message = "HTTP1.1 server, receiving request "
                "for something other than 1.1";
        error_name = "HTTP_VERSION_NOT_SUPPORTED";
    } else if (error_type == 501) {
        error_message = "Method requested is unimplemented, sorry :(";
        error_name = "NOT_IMPLEMENTED";
    } else if (error_type == 500) {
        error_message = "Server error, could be caused from bad input "
                "that was not handled";
        error_name = "INTERNAL_SERVER_ERROR";
    } else if (error_type == 503) {
        error_message = "Can not accept anymore connections";
        error_name = "SERVICE_UNAVAILABLE";
    } else if (error_type == 411) {
        error_message = "Post request requires a content length";
        error_name = "LENGTH_REQUIRED";
    } else if (error_type == 404) {
        error_message = "Could not find file";
        error_name = "NOT_FOUND";
    } else if (error_type == 400) {
        error_message = "Recieved bad request";
        error_name = "BAD_REQUEST";
    }

    // HTTP response body
    sprintf(body,
            "<html><title>Error Page</title>"
                    "<body>\r\n"
                    "%d Error --- %s </body></html>\r\n",
            error_type, error_message);

    // HTTP response header
    sprintf(head,
            "HTTP/1.1 %d %s\r\n"
                    "Date: %s\r\n"
                    "Server: Lisod/1.0\r\n"
                    "Content-type: text/html\r\n"
                    "Content-length: %d\r\n\r\n",
            error_type, error_name, date, (int) strlen(body));


    swrite(head, strlen(head), id, clients);
    swrite(body, strlen(head), id, clients);
}

void parse_uri(char *filename, char *uri, char *cgiargs, int *is_static) {

    char *ptr;

    if (!strstr(uri, "/cgi")) {
        *is_static = 1;
        strcpy(cgiargs, "");
        strcpy(filename, server->www_path);
        strcat(filename, uri);
        if (uri[strlen(uri) - 1] == '/')
            strcat(filename, "index.html");
        return;
    }
    else {
        *is_static = 0;
        ptr = index(uri, '?');
        if (ptr) {
            strcpy(cgiargs, ptr + 1);
            *ptr = '\0';
        }
        else
            strcpy(cgiargs, "");
        strcpy(filename, server->cgi_path);
        strcat(filename, uri + 4);
        return;
    }
}

void serve_static(char *method, char *filename, int body_size, int id,
                  struct client_set *clients) {
    if (!strcmp(method, "GET")) {
        send_get(id, clients, filename);
    }

    if (!strcmp(method, "HEAD")) {
        send_head(id, clients, filename);
    }

    if (!strcmp(method, "POST")) {
        if (!body_size) {
            string_log(0, "Using POST without content_length, "
                    "sending 411\n");
            send_error(id, clients, 411);
        } else {
            send_post(id, clients);
        }
    }
}

void execve_error_handler() {
    switch (errno) {
        case E2BIG:
            fprintf(stderr, "The total number of bytes in the environment"
                    "(envp) and argument list (argv) is too large.\n");
            return;
        case EACCES:
            fprintf(stderr,
                    "Execute permission is denied for the file or a script or "
                            "ELF interpreter.\n");
            return;
        case EFAULT:
            fprintf(stderr,
                    "filename points outside your accessible address space.\n");
            return;
        case EINVAL:
            fprintf(stderr,
                    "An ELF executable had more than one PT_INTERP segment "
                            "(i.e., tried to name more than one interpreter).\n");
            return;
        case EIO:
            fprintf(stderr, "An I/O error occurred.\n");
            return;
        case EISDIR:
            fprintf(stderr, "An ELF interpreter was a directory.\n");
            return;
        case ELOOP:
            fprintf(stderr,
                    "Too many symbolic links were encountered in resolving "
                            "filename or the name of a script or ELF "
                            "interpreter.\n");
            return;
        case EMFILE:
            fprintf(stderr,
                    "The process has the maximum number of files open.\n");
            return;
        case ENAMETOOLONG:
            fprintf(stderr, "filename is too long.\n");
            return;
        case ENFILE:
            fprintf(stderr,
                    "The system limit on the total number of open files "
                            "has been reached.\n");
            return;
        case ENOENT:
            fprintf(stderr,
                    "The file filename or a script or ELF interpreter does "
                            "not exist, or a shared library needed for file "
                            "or interpreter cannot be found.\n");
            return;
        case ENOEXEC:
            fprintf(stderr,
                    "An executable is not in a recognised format, is for "
                            "the wrong architecture, or has some other format "
                            "error that means it cannot be executed.\n");
            return;
        case ENOMEM:
            fprintf(stderr, "Insufficient kernel memory was available.\n");
            return;
        case ENOTDIR:
            fprintf(stderr,
                    "A component of the path prefix of filename or a script or "
                            "ELF interpreter is not a directory.\n");
            return;
        case EPERM:
            fprintf(stderr,
                    "The file system is mounted nosuid, the user is not the "
                            "superuser, and the file has an SUID or "
                            "SGID bit set.\n");
            return;
        case ETXTBSY:
            fprintf(stderr,
                    "Executable was open for writing by one or more "
                            "processes.\n");
            return;
        default:
            fprintf(stderr, "Unkown error occurred with execve().\n");
            return;
    }
}

void serve_dynamic(char *method, char *filename, char *uri, int body_size,
                   int id, struct client_set *clients, char *cgiargs,
                   struct http_request *http_request) {
    struct client *curr_client;
    struct sockaddr_in addr;
    char clientip[20];
    pid_t pid;
    int stdin_pipe[2];
    int stdout_pipe[2];
    int readret;
    char buf[BUF_SIZE];

    char *ENVP[23];
    char *ARGV[] = {
            filename,
            NULL
    };

    ENVP[0] = calloc(sizeof(char), MIN_BUF);
    ENVP[1] = calloc(sizeof(char), MIN_BUF);
    ENVP[2] = calloc(sizeof(char), MIN_BUF);
    ENVP[3] = calloc(sizeof(char), MIN_BUF);
    ENVP[4] = calloc(sizeof(char), MIN_BUF);
    ENVP[5] = calloc(sizeof(char), MIN_BUF);
    ENVP[6] = calloc(sizeof(char), MIN_BUF);
    ENVP[7] = calloc(sizeof(char), MIN_BUF);
    ENVP[8] = calloc(sizeof(char), MIN_BUF);
    ENVP[9] = calloc(sizeof(char), MIN_BUF);
    ENVP[10] = calloc(sizeof(char), MIN_BUF);
    ENVP[11] = calloc(sizeof(char), MIN_BUF);
    ENVP[12] = calloc(sizeof(char), MIN_BUF);
    ENVP[13] = calloc(sizeof(char), MIN_BUF);
    ENVP[14] = calloc(sizeof(char), MIN_BUF);
    ENVP[15] = calloc(sizeof(char), MIN_BUF);
    ENVP[16] = calloc(sizeof(char), MIN_BUF);
    ENVP[17] = calloc(sizeof(char), MIN_BUF);
    ENVP[18] = calloc(sizeof(char), MIN_BUF);
    ENVP[19] = calloc(sizeof(char), MIN_BUF);
    ENVP[20] = calloc(sizeof(char), MIN_BUF);
    ENVP[21] = calloc(sizeof(char), MIN_BUF);
    ENVP[22] = calloc(sizeof(char), MIN_BUF);

    curr_client = clients->client_arr[id];
    socklen_t addr_size = sizeof(struct sockaddr_in);
    getpeername(curr_client->fd, (struct sockaddr *) &addr, &addr_size);
    strcpy(clientip, inet_ntoa(addr.sin_addr));

    // Set REMOTE_ADDR
    sprintf(ENVP[0], "REMOTE_ADDR=%s", clientip);

    sprintf(ENVP[1], "SCRIPT_NAME=/cgi");

    // Set SERVER_PORT
    if (curr_client->is_secure) {
        sprintf(ENVP[2], "SERVER_PORT=%d", server->secure_sock);
    } else {
        sprintf(ENVP[2], "SERVER_PORT=%d", server->sock);
    }

    sprintf(ENVP[3], "SERVER_PROTOCOL=HTTP/1.1");

    sprintf(ENVP[4], "SERVER_SOFTWARE=Liso/1.0");

    sprintf(ENVP[5], "GATEWAY_INTERFACE=CGI/1.1");

    // Set PATH_INFO
    sprintf(ENVP[6], "PATH_INFO=%s", uri + 4);

    // Set QUERY_STRING
    sprintf(ENVP[7], "QUERY_STRING=%s", cgiargs);

    // Set REQUEST_URI
    sprintf(ENVP[8], "REQUEST_URI=%s", uri);

    // Set REQUEST_METHOD
    sprintf(ENVP[9], "REQUEST_METHOD=%s", method);

    // Set CONTENT_LENGTH
    sprintf(ENVP[10], "CONTENT_LENGTH=%d", body_size);

    // Set CONTENT_TYPE
    sprintf(ENVP[11], "CONTENT_TYPE=%s", http_request->content_type);

    // Set HTTP_ACCEPT
    sprintf(ENVP[12], "HTTP_ACCEPT=%s", http_request->accept);

    // Set HTTP_REFERER
    sprintf(ENVP[13], "HTTP_REFERER=%s", http_request->referer);

    // Set HTTP_ACCEPT_ENCODING
    sprintf(ENVP[14], "HTTP_ACCEPT_ENCODING=%s", http_request->accept_encoding);

    // Set HTTP_ACCEPT_LANGUAGE
    sprintf(ENVP[15], "HTTP_ACCEPT_LANGUAGE=%s", http_request->accept_encoding);

    // Set HTTP_ACCEPT_CHARSET
    sprintf(ENVP[16], "HTTP_ACCEPT_CHARSET=%s", http_request->accept_charset);

    // Set HTTP_COOKIE
    sprintf(ENVP[17], "HTTP_COOKIE=%s", http_request->cookie);

    // Set HTTP_USER_AGENT
    sprintf(ENVP[18], "HTTP_USER_AGENT=%s", http_request->user_agent);

    // Set HTTP_CONNECTION
    if (curr_client->is_alive) {
        sprintf(ENVP[19], "HTTP_CONNECTION=keep-alive");
    } else {
        sprintf(ENVP[19], "HTTP_CONNECTION=close");
    }

    // Set HTTP_HOST
    sprintf(ENVP[20], "HTTP_HOST=%s", http_request->host);

    sprintf(ENVP[21], "SERVER_NAME=lisod/1.1");

    // Set NULL
    ENVP[22] = NULL;

    if (pipe(stdin_pipe) < 0) {
        fprintf(stderr, "Error piping for stdin.\n");
        return;
    }

    if (pipe(stdout_pipe) < 0) {
        fprintf(stderr, "Error piping for stdout.\n");
        return;
    }

    pid = fork();
    /* Error */
    if (pid < 0) {
        fprintf(stderr, "Something really bad happened when fork()ing.\n");
        return;
    }

    /* Child */
    if (pid == 0) {
        dup2(stdout_pipe[1], fileno(stdout));
        dup2(stdin_pipe[0], fileno(stdin));
        /* you should probably do something with stderr */
        close(stdout_pipe[0]);
        close(stdin_pipe[1]);

        /* pretty much no matter what, if it returns bad things happened... */
        if (execve(filename, ARGV, ENVP)) {
            execve_error_handler();
            fprintf(stderr, "Error executing execve syscall.\n");
            return;
        }
    }

    /* Parent */
    if (pid > 0) {
        fprintf(stdout, "Parent: Heading to select() loop.\n");
        dup2(curr_client->fd, STDOUT_FILENO);
        close(stdout_pipe[1]);
        close(stdin_pipe[0]);

        if (!body_size && !strcmp("POST",method)) {
            string_log(0, "Using POST without content_length, "
                    "sending 411\n");
            send_error(id, clients, 411);
        } else {
            if ((curr_client->request_body != NULL) && (write(stdin_pipe[1], curr_client->request_body,
                      strlen(curr_client->request_body)) < 0)) {
                fprintf(stderr,
                        "Error writing to spawned CGI program.\n");
                return;
            }
        }

//        close(stdin_pipe[1]); /* finished writing to spawn */

        add_cgi_client(clients, stdout_pipe[0], curr_client->client_id);

//        close(stdin_pipe[1]);

    }

}

void get_request_message(int id, struct client_set *clients) {
    struct client *curr_client;
    char *term;

    int body_size;

    body_size = 0;
    curr_client = clients->client_arr[id];
    curr_client->request_header = calloc(sizeof(char),
                                         curr_client->buffer_size);

    while ((term = strstr(curr_client->read_buf, "\r\n\r\n"))) {
        char uri[MIN_BUF];
        char method[MIN_BUF];
        char filename[MIN_BUF];
        char cgiargs[MIN_BUF];
        struct http_request *http_request;

        http_request = malloc(sizeof(struct http_request));

        int is_static;

        term[0] = '\0';

        strcpy(curr_client->request_header, curr_client->read_buf);

        while (curr_client->read_buf[0] != '\0') {
            curr_client->read_buf++;
        }

        curr_client->read_buf += 4;

        if (!parse_request_header(id, clients, &body_size, method,
                                  uri, http_request)) {
            continue;
        }

        if (body_size > 0) {
            if (!get_request_body(id, clients, body_size)) {
                continue;
            }
        }

        if (strcmp(method, "GET") &&
            strcmp(method, "POST") &&
            strcmp(method, "HEAD")) {
            string_log(0, "Method unimplemented, sending 501\n");
            send_error(id, clients, 501);
            continue;
        }

        parse_uri(filename, uri, cgiargs, &is_static);

        if (is_static) {
            serve_static(method, filename, body_size, id, clients);
        } else {
            serve_dynamic(method, filename, uri, body_size, id, clients,
                          cgiargs, http_request);
        }

        if (!curr_client->is_alive) {
            close_client(id, clients);
            break;
        }
    }

}

int read_request(int id, struct client_set *clients) {
    ssize_t readret;
    int fd;

    struct client *curr_client;

    curr_client = clients->client_arr[id];
    fd = curr_client->fd;

    if (curr_client->cgi_flag) {

        struct client *cgi_client;
        cgi_client = clients->client_arr[curr_client->cgi_client_id];

        if ((readret = read(curr_client->fd,
                               curr_client->read_buf +
                               curr_client->read_buffer_marker,
                               BUF_SIZE - 1)) > 0) {
            curr_client->read_buffer_marker += readret;
            if (readret == BUF_SIZE - 1) {
                curr_client->buffer_size += BUF_SIZE;
                char *new_buf = calloc(sizeof(char), curr_client->buffer_size);
                strcpy(new_buf, curr_client->read_buf);
                curr_client->read_buf = new_buf;
            }
        }

        swrite(curr_client->read_buf, curr_client->buffer_size,
               cgi_client->client_id, clients);

        if (readret == -1) {
            string_log(0, "Error has occurred in reading client %d\n", fd);
            close_socket(fd);
            close_socket(server->secure_sock);
            close_socket(server->sock);
            close(curr_client->fd);
            return 0;
        }

        if (readret == 0) {
            close_client(id, clients);
            string_log(0,
                    "CGI spawned process returned with EOF as expected.\n");
        }

        curr_client->read_buffer_marker = (int) strlen(curr_client->read_buf);
    }
    else {
        if ((readret = sread(id, clients,
                             curr_client->read_buf +
                             curr_client->read_buffer_marker,
                             BUF_SIZE - 1)) > 0) {

            curr_client->read_buffer_marker += readret;
            if (readret == BUF_SIZE - 1) {
                curr_client->buffer_size += BUF_SIZE;
                char *new_buf = calloc(sizeof(char), curr_client->buffer_size);
                strcpy(new_buf, curr_client->read_buf);
                curr_client->read_buf = new_buf;
            }

            if (strstr(curr_client->read_buf, "\r\n\r\n")) {
                get_request_message(id, clients);
            }
        }

        if (readret == -1) {
            string_log(0, "Error has occurred in reading client %d\n", fd);
            close_socket(fd);
            close_socket(server->secure_sock);
            close_socket(server->sock);
            return 0;
        }

            // Client has performed an orderly shutdown
        else if (readret == 0) {
            string_log(0, "Client %d has performed an orderly shutdown\n", fd);
            close_client(id, clients);
        }

        curr_client->read_buffer_marker = (int) strlen(curr_client->read_buf);
    }

    return 1;
}


int get_request_body(int id, struct client_set *clients, int body_size) {
    struct client *curr_client;
    char *temp_read_buf;
    size_t curr_size, bytes_to_read;
    ssize_t readret;

    curr_client = clients->client_arr[id];

    temp_read_buf = calloc(sizeof(char), strlen(curr_client->read_buf));
    curr_client->request_body = calloc(sizeof(char), (size_t) body_size);

    strcpy(temp_read_buf, curr_client->read_buf);

    temp_read_buf[body_size] = '\0';

    strcpy(curr_client->request_body, temp_read_buf);

    curr_size = strlen(curr_client->read_buf);

    if (body_size > curr_size) {
        bytes_to_read = body_size - curr_size;

        char buf[bytes_to_read];

        if ((readret = sread(id, clients,
                             buf, (int) bytes_to_read)) < bytes_to_read) {
            strcat(curr_client->request_body, buf);
            string_log(1, "new request_body: %s, readret: %zd\n",
                       curr_client->request_body, readret);
            curr_client->read_buffer_marker += readret;
        }
    } else if (body_size == curr_size) {
        strcpy(curr_client->request_body, temp_read_buf);
    }

    return 1;
}

int numbers_only(char *s) {
    int i;
    for (i = 0; i < strlen(s); i++) {
        if (s[i] != ' ' && !strchr("0123456789", s[i])) {
            return 0;
        }
    }

    return 1;
}

int parse_request_header(int id, struct client_set *clients, int *body_size,
                         char *method, char *uri,
                         struct http_request *http_request) {
    char version[MIN_BUF];
    char uri_copy[MIN_BUF];
    char *term;

    *body_size = 0;

    struct client *curr_client;
    curr_client = clients->client_arr[id];

    if (strlen(curr_client->request_header) > 8192) {
        string_log(0, "Request header is too large, sending 500\n");
        send_error(id, clients, 500);
        return 0;
    }

    if (!parse_requestline(id, clients, method, uri, version)) {
        string_log(0, "Error: parse requestline\n");
        return 0;
    }

    strcpy(uri_copy, uri);

    if (strcmp(version, "HTTP/1.1")) {
        string_log(0, "Version other than HTTP/1.1, sending 505.\n");
        send_error(id, clients, 505);
        return 0;
    }

    if (strstr(curr_client->request_header, "Content-Length:")) {
        char *content_len;
        char temp[BUF_SIZE];
        strcpy(temp, curr_client->request_header);
        content_len = strstr(temp, "Content-Length:");
        content_len += 15;
        if ((term = strstr(content_len, "\r\n"))) {
            term[0] = '\0';
        } else if ((term = strchr(content_len, '\0'))) {
            term[0] = '\0';
        }

        if (!numbers_only(content_len)) {
            string_log(0, "String in the content length, sending 400.\n");
            send_error(id, clients, 400);
            return 0;
        }

        if (atoi(content_len) < 0) {
            string_log(0, "Negative number given in the content length, "
                    "sending 400.\n");
            send_error(id, clients, 400);
            return 0;
        }

        *body_size = atoi(content_len);
    }

    if (strstr(curr_client->request_header, "Connection:")) {
        char *closed;
        char temp[BUF_SIZE];
        strcpy(temp, curr_client->request_header);
        closed = strstr(temp, "Connection:");
        closed += 11;
        if ((term = strstr(closed, "\r\n"))) {
            term[0] = '\0';
        } else if ((term = strchr(closed, '\0'))) {
            term[0] = '\0';
        }

        if (!strcmp(closed, "closed")) {
            curr_client->is_alive = 0;
        } else if (!strcmp(closed, " closed")) {
            curr_client->is_alive = 0;
        }
    }

    if (strstr(curr_client->request_header, "Content-Type:")) {
        char *ctype;
        char temp[BUF_SIZE];
        strcpy(temp, curr_client->request_header);
        ctype = strstr(temp, "Content-Type:");
        ctype += strlen("Content-Type:");
        if ((term = strstr(ctype, "\r\n"))) {
            term[0] = '\0';
        } else if ((term = strchr(ctype, '\0'))) {
            term[0] = '\0';
        }
        strcpy(http_request->content_type, ctype);
    } else {
        http_request->content_type[0] = '\0';
    }

    if (strstr(curr_client->request_header, "Accept:")) {
        char *accept;
        char temp[BUF_SIZE];
        strcpy(temp, curr_client->request_header);
        accept = strstr(temp, "Accept:");
        accept += strlen("Accept:");
        if ((term = strstr(accept, "\r\n"))) {
            term[0] = '\0';
        } else if ((term = strchr(accept, '\0'))) {
            term[0] = '\0';
        }
        strcpy(http_request->accept, accept);
    } else {
        http_request->accept[0] = '\0';
    }

    if (strstr(curr_client->request_header, "Referer:")) {
        char *referer;
        char temp[BUF_SIZE];
        strcpy(temp, curr_client->request_header);
        referer = strstr(temp, "Referer:");
        referer += strlen("Referer:");
        if ((term = strstr(referer, "\r\n"))) {
            term[0] = '\0';
        } else if ((term = strchr(referer, '\0'))) {
            term[0] = '\0';
        }
        strcpy(http_request->referer, referer);
    } else {
        http_request->referer[0] = '\0';
    }

    if (strstr(curr_client->request_header, "Accept-Encoding:")) {
        char *enc;
        char temp[BUF_SIZE];
        strcpy(temp, curr_client->request_header);
        enc = strstr(temp, "Accept-Encoding:");
        enc += strlen("Accept-Encoding:");
        if ((term = strstr(enc, "\r\n"))) {
            term[0] = '\0';
        } else if ((term = strchr(enc, '\0'))) {
            term[0] = '\0';
        }
        strcpy(http_request->accept_encoding, enc);
    } else {
        http_request->accept_encoding[0] = '\0';
    }

    if (strstr(curr_client->request_header, "Accept-Language:")) {
        char *lang;
        char temp[BUF_SIZE];
        strcpy(temp, curr_client->request_header);
        lang = strstr(temp, "Accept-Language:");
        lang += strlen("Accept-Language:");
        if ((term = strstr(lang, "\r\n"))) {
            term[0] = '\0';
        } else if ((term = strchr(lang, '\0'))) {
            term[0] = '\0';
        }
        strcpy(http_request->accept_language, lang);
    } else {
        http_request->accept_language[0] = '\0';
    }

    if (strstr(curr_client->request_header, "Accept-Charset:")) {
        char *charset;
        char temp[BUF_SIZE];
        strcpy(temp, curr_client->request_header);
        charset = strstr(temp, "Accept-Charset:");
        charset += strlen("Accept-Charset:");
        if ((term = strstr(charset, "\r\n"))) {
            term[0] = '\0';
        } else if ((term = strchr(charset, '\0'))) {
            term[0] = '\0';
        }
        strcpy(http_request->accept_charset, charset);
    } else {
        http_request->accept_charset[0] = '\0';
    }

    if (strstr(curr_client->request_header, "Cookie:")) {
        char *cook;
        char temp[BUF_SIZE];
        strcpy(temp, curr_client->request_header);
        cook = strstr(temp, "Cookie:");
        cook += strlen("Cookie:");
        if ((term = strstr(cook, "\r\n"))) {
            term[0] = '\0';
        } else if ((term = strchr(cook, '\0'))) {
            term[0] = '\0';
        }
        strcpy(http_request->cookie, cook);
    } else {
        http_request->cookie[0] = '\0';
    }

    if (strstr(curr_client->request_header, "User-Agent:")) {
        char *agen;
        char temp[BUF_SIZE];
        strcpy(temp, curr_client->request_header);
        agen = strstr(temp, "User-Agent:");
        agen += strlen("User-Agent::");
        if ((term = strstr(agen, "\r\n"))) {
            term[0] = '\0';
        } else if ((term = strchr(agen, '\0'))) {
            term[0] = '\0';
        }
        strcpy(http_request->user_agent, agen);
    } else {
        http_request->user_agent[0] = '\0';
    }

    if (strstr(curr_client->request_header, "Host:")) {
        char *host;
        char temp[BUF_SIZE];
        strcpy(temp, curr_client->request_header);
        host = strstr(temp, "Host:");
        host += strlen("Host:");
        if ((term = strstr(host, "\r\n"))) {
            term[0] = '\0';
        } else if ((term = strchr(host, '\0'))) {
            term[0] = '\0';
        }
        strcpy(http_request->host, host);
    } else {
        http_request->host[0] = '\0';
    }

    string_log(1, "Recieved request header %s\n", curr_client->request_header);
    return 1;
}


int parse_requestline(int id, struct client_set *clients, char *method,
                      char *uri, char *version) {
    struct client *curr_client;
    char *req_header;
    char *line;

    curr_client = clients->client_arr[id];
    req_header = calloc(sizeof(char), curr_client->buffer_size);

    strcpy(req_header, curr_client->request_header);

    if ((line = strstr(req_header, "\r\n"))) {
        line[0] = '\0';
    } else {
        string_log(0, "Error: strstr should've returned in requestline\n");
    }

    if (sscanf(req_header, "%s %s %s", method, uri, version) < 3) {
        string_log(0, "Error: sscanf in requestline\n");
        return 0;
    }

    return 1;
}

void parse_filetype(char *filename, char *filetype) {
    if (strstr(filename, ".html")) {
        strcpy(filetype, "text/html");
    } else if (strstr(filename, ".css")) {
        strcpy(filetype, "text/css");
    } else if (strstr(filename, ".js")) {
        strcpy(filetype, "application/javascript\0");
    } else if (strstr(filename, ".png")) {
        strcpy(filetype, "image/png");
    } else if (strstr(filename, ".jpg")) {
        strcpy(filetype, "image/jpeg");
    } else {
        strcpy(filetype, "text/plain");
    }
}

void send_head(int id, struct client_set *clients, char *filename) {
    char head[MIN_BUF];
    char date[MIN_BUF];
    char mod_date[MIN_BUF];
    char filetype[MIN_BUF];
    struct stat stat_buf;
    char *file;
    int fd;

    struct client *curr_client;

    curr_client = clients->client_arr[id];

    stat(filename, &stat_buf);

    parse_filetype(filename, filetype);

    time_t now = time(0);
    struct tm tm = *gmtime(&now);
    strftime(date, MIN_BUF, "%a, %d %b %Y %H:%M:%S %Z", &tm);

    if ((fd = open(filename, O_RDONLY, 0)) < 0) {
        string_log(1, "Cannot find file, sending 404\n");
        send_error(id, clients, 404);
        return;
    }

    file = (char *) mmap(0, (size_t) stat_buf.st_size,
                         PROT_READ, MAP_SHARED, fd, 0);

    strftime(mod_date, 20, "%a, %d %b %Y %H:%M:%S %Z",
             localtime(&(stat_buf.st_ctime)));

    if (!curr_client->is_alive) {
        sprintf(head,
                "HTTP/1.1 200 OK\r\n"
                        "Date: %s\r\n"
                        "Server: Liso/1.0\r\n"
                        "Content-Length: %zd\r\n"
                        "Connection: closed\r\n"
                        "Content-Type: %s\r\n"
                        "Last-Modified: %s\r\n\r\n",
                date, (size_t) stat_buf.st_size, filetype, mod_date);
    } else {
        sprintf(head,
                "HTTP/1.1 200 OK\r\n"
                        "Date: %s\r\n"
                        "Server: Liso/1.0\r\n"
                        "Content-Length: %zd\r\n"
                        "Connection: keep-alive\r\n"
                        "Content-Type: %s\r\n"
                        "Last-Modified: %s\r\n\r\n",
                date, (size_t) stat_buf.st_size, filetype, mod_date);
    }

    string_log(1, "Sending GET header: %s to client %d\n",
               head, curr_client->fd);

    swrite(head, strlen(head), id, clients);

    munmap(file, (size_t) stat_buf.st_size);

    close(fd);

}

void send_post(int id, struct client_set *clients) {
    char head[MIN_BUF];
    char date[MIN_BUF];
    struct client *curr_client;

    curr_client = clients->client_arr[id];

    time_t now = time(0);
    struct tm tm = *gmtime(&now);
    strftime(date, MIN_BUF, "%a, %d %b %Y %H:%M:%S %Z", &tm);

    // send response headers to client
    sprintf(head, "HTTP/1.1 200 OK\r\n"
            "Date: %s\r\n"
            "Server: Liso/1.0\r\n"
            "Content-Length: 0\r\n"
            "Content-Type: text/html\r\n", date);

    string_log(1, "Sending POST header: %s to client %d\n",
               head, curr_client->fd);

    swrite(head, strlen(head), id, clients);
}

int send_get(int id, struct client_set *clients, char *filename) {
    struct stat stat_buf;
    char *file;
    int fd;

    // Sending the head of the request
    send_head(id, clients, filename);

    if ((fd = open(filename, O_RDONLY, 0)) < 0) {
        string_log(0, "Cannot find file, sending 404.\n");
        send_error(id, clients, 404);
        return 0;
    }

    stat(filename, &stat_buf);

    file = (char *) mmap(0, (size_t) stat_buf.st_size,
                         PROT_READ, MAP_SHARED, fd, 0);

    swrite(file, (size_t) stat_buf.st_size, id, clients);

    munmap(file, (size_t) stat_buf.st_size);

    close(fd);

    return 1;
}

int isfull(struct server_state state, struct client_set *clients) {
    int count, i;

    count = 0;

    for (i = 0; i < FD_SETSIZE; i++) {
        if (clients->client_arr[i]->fd > 0) {
            count++;
        }
    }

    if (state.full <= count) {
        return 1;
    }

    return 0;
}