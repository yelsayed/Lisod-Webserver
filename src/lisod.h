#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <errno.h>

#include "state.h"
#include "ssl.h"
#include "log.h"

#define BUF_SIZE 8192
#define MIN_BUF 256

// Stores some aspects of an HTTP Request. Specifically ones missed in cp2
struct http_request {
    char content_type[MIN_BUF];
    char accept[MIN_BUF];
    char referer[MIN_BUF];
    char accept_encoding[MIN_BUF];
    char accept_language[MIN_BUF];
    char accept_charset[MIN_BUF];
    char cookie[MIN_BUF];
    char user_agent[MIN_BUF];
    char host[MIN_BUF];
};

// Contains all the information relevant to one client
struct client {
    int fd;
    int client_id;
    int read_buffer_marker;
    int is_alive;
    int is_secure;
    SSL *client_context;
    size_t buffer_size;
    char *request_header;
    char *request_body;
    char *read_buf;

    int cgi_flag;
    int cgi_client_id;
};

// Contains all the clients that select will work with
struct client_set {
    int nfds;
    int rfds; // Number of Ready file descriptors
    fd_set read_set;
    fd_set ready_set;
    fd_set write_set;

    // Contains the file descriptor of each client
    struct client *client_arr[FD_SETSIZE];
};

typedef struct client_set client_set;

//TODO: Documentation for this function
int add_cgi_client(struct client_set *clients, int stdout_pipe, int client_id);

/* close_socket
 *  This function is responsible for closing the socket,
 *  usually used for closing the listening socket
 *
 *  Parameters:
 *      sock - listening socket of the server (usually)
 */
int close_socket(int sock);

/* init_client_set
 *  client_set is the global set of all the clients
 *  sock is the listening socket for this HTTPS Server
 *
 *  Parameters:
 *      clients     - set of all the clients currently connected to the server
 */
void init_client_set(struct client_set *clients, struct server_state *state);

/* add_client
 *  Adds a client to the existing list of clients given the socket
 *  retrieved from accept() function.
 *
 *  Parameters:
 *      client_sock    - socket of the client from accept()
 *      client_set     - set of all the clients
 *      secure         - tells if the client is connected to a secure port
 *      client_context - if this client is securely connected, we need this
 */
int add_client(int client_sock, struct client_set *clients, int secure,
               SSL *client_context);

/* close_client
 *  Closes the client by closing the socket, and freeing space for another
 *  client to connect in the future. This also frees any buffers this client
 *  might have been using.
 *
 *  Parameters:
 *      clients - set of all the clients
 */
int close_client(int id, struct client_set *clients);

/* process_clients
 *  This function will go through all the clients in the client
 *  set and then read the requests of each client. This is only,
 *  if select() returns that a client wants to send/recv.
 *
 *  Parameters:
 *      clients - set of all the clients
 *      state   - state of the webserver that contains all the input parameters
 */
int process_clients(struct client_set *clients, struct server_state *state);

// TODO documententation for this function
void serve_static(char *method, char *filename, int body_size, int id,
                  struct client_set *clients);

// TODO documentation for this function
void serve_dynamic(char *method, char *filename, char *uri, int body_size,
                   int id, struct client_set *clients, char *cgiargs,
                   struct http_request *http_request);

/* get_request_message
 *  Returns the entire request message from the client read buffer
 *
 *  Parameters:
 *      secure_sock - secure listening socket of the server
 *      sock    - listening socket of the server
 *      id      - identifier of the client
 *      clients - set of all clients
 */
void get_request_message(int id, struct client_set *clients);

/* read_request
 *  Given a client this will receive what the client wants to send
 *  This function is also responsible for calling the function that processes
 *  the requests on the read buffer.
 *
 *  Parameters:
 *      sock    - listening socket of the server
 *      secure_sock - secure listening socket of the server
 *      id      - identifier of the client
 *      clients - set of all clients
 */
int read_request(int id, struct client_set *clients);

/* parse_request_header
 *  Given a client that has a read buffer of whatever he sent in the
 *  previous call to read_request, this will parse that buffer and retrieve
 *  the header lines of the header. The buffer should be stored in the
 *  client struct.
 *
 *  Parameters:
 *      id      - identifier of the client
 *      clients - set of all clients
 *      TODO: make sure to complete the params
 */
int parse_request_header(int id, struct client_set *clients, int *body_size,
                         char *method, char *uri, struct http_request *http_request);

/* parse_requestline
 *  This is the first call from the parse_request_header function.
 *  This will retrieve the method name, version, and uri to be used by
 *  the server
 *
 *  Parameters:
 *      id        - identifier of the client
 *      clients   - set of all clients
 *      method    - string that will store the method
 *      version   - string that will store the http version
 *      uri       - string that will store the uri
 */
int parse_requestline(int id, struct client_set *clients, char *method,
                      char *uri, char *version);

/* send_get
 *  This will send the file for the GET request made
 *  by a client. This will call the send_head to send the headers.
 *
 *  Parameters:
 *      id       - identifier of the client
 *      clients  - set of all clients
 *      filename - string containing the filename
 */
int send_get(int id, struct client_set *clients, char *filename);

/* send_head
 *  This will send the headers for the GET/HEAD requests made
 *  by a client.
 *
 *  Parameters:
 *      id       - identifier of the client
 *      clients  - set of all clients
 *      filename - string containing the filename
 */
void send_head(int id, struct client_set *clients, char *filename);

/* send_post
 *  This will send the headers for the POST requests made
 *  by a client.
 *
 *  Parameters:
 *      id      - identifier of the client
 *      clients - set of all clients
 */
void send_post(int id, struct client_set *clients);

/* send_error
 *  Sends a predetermined error message and body to the client. The message and
 *  body are determined through the input of this function.
 *
 *  Parameters:
 *      id         - identifier of the client
 *      clients    - set of all the clients
 *      error_type - gives the error number that is to be sent to the client
 *
 *  Special Note:
 *      Some code retrieved from:
 *      http://stackoverflow.com/questions/7548759/generate-a-date-string-in-http-response-date-format-in-c
 */
void send_error(int id, struct client_set *clients, int error_type);

/* get_request_body
 *  Returns the request body given the client, read buffer
 *  and the request headers. Should be called only when
 *  you have content length
 *
 *  Parameters:
 *      body_size - contains an integer value for content length
 *      id      - identifier of the client
 *      clients - set of all clients
 */
int get_request_body(int id, struct client_set *clients, int body_size);

/* isfull
 *  checks if the client set is full given the state which provides
 *  a maximum number of clients that can connect at time.
 *
 *  Parameters:
 *      state - contains information about the state
 */
int isfull(struct server_state state, struct client_set *clients);


/* numbers_only
 *  Checks if a string has only numbers in it's content
 *
 *  Parameters:
 *      s - string to be checked
 */
int numbers_only(char *s);

/* parse_filetype
 *  Returns the file type given the filename through simple parsing
 *
 *  Parameters:
 *      filename - contains filename of the file
 *      filetype - contains the type of the file
 */
void parse_filetype(char *filename, char *filetype);

/* parse_uri
 *  Retrieves filename, cgi arguments, and a flag indicating if
 *  request is dynamic from uri, should be elastic enough to handle
 *  some handles or informalities
 *
 *  Parameters:
 *      filename  - buffer that will be filled by this function
 *      uri       - uri buffer that contains the filename
 *      cgiargs   - arguments that'll be passed into cgi script
 *      is_static - indicates whether request is dynamic or not
 */
void parse_uri(char *filename, char *uri, char *cgiargs, int *is_static);

/* sread
 *  Securely reads from the client. This is a wrapper for the recv function.
 *  Should be called regardless of the client being secure or not.
 *
 *  Parameters:
 *      id      - identifier of the client
 *      clients - set of all the clients
 *      buf     - buffer to be read into
 *      len     - number of bytes to read from the client
 */
ssize_t sread(int id, struct client_set *clients, char *buf, int len);

/* swrite
 *  Securely writes to the client. This is a wrapper for the send function.
 *  Should be called regardless of the client being secure or not.
 *
 *  Parameters:
 *      id      - identifier of the client
 *      clients - set of all the clients
 *      buf     - buffer to be write to the client
 *      len     - number of bytes to write to the client
 */
ssize_t swrite(char *buf, size_t len, int id, struct client_set *clients);