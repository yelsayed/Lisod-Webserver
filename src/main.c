/******************************************************************************
* main.c                                                                      *
*                                                                             *
* Description: This file contains the C source code for the server. The       *
*                   server is a lisod webserver that implements HEAD, POST,   *
*                   and GET. This complies with the HTTP 1.1 protocal.        *
*                                                                             *
* Usage: ./lisod <HTTP port> <HTTPS port> <log file> <lock file>              *
* <www folder> <CGI script path> <private key file> <certificate file>        *
*     Param: HTTP port – the port for the HTTP (or echo) server to listen on  *
*     Param: HTTPS port – the port for the HTTPS server to listen on          *
*     Param: log file – file to send log messages to (debug, info, error)     *
*     Param: lock file – file to lock on when becoming a daemon process       *
*     Param: www folder – folder containing a tree to serve as the root       *
*                           of a website                                      *
*     Param: CGI script name (or folder) – for this project, this is a file   *
*               that should be a script where you redirect all /cgi/  URIs.   *
*     Param: In the real world, this would likely be a directory of           *
*               executable programs.                                          *
*     Param: private key file – private key file path                         *
*     Param: certificate file – certificate file path                         *
*                                                                             *
* Authors: Yasser El-Sayed <yelsayed@cmu.edu>                                 *
*                                                                             *
*******************************************************************************/

#include "lisod.h"
#include "daemonize.h"

int main(int argc, char *argv[]) {
    SSL_load_error_strings();
    SSL_library_init();
    int sock, client_sock, secure_sock;
    socklen_t cli_size;
    struct server_state state;
    struct sockaddr_in addr, cli_addr;

    signal(SIGPIPE, SIG_IGN);

    if (argc != 9) {
        string_log(1, "Incorrect number of argument. \n"
                "Usage: ./lisod <HTTP port> <HTTPS port> <string_log file> "
                "<lock file> <www folder> <CGI script path> <private key file>"
                " <certificate file> \n");
        return EXIT_FAILURE;
    }

    // Check for null args
    if (!argv[1] || !argv[2] || !argv[3] || !argv[4] || !argv[5] || !argv[6]
        || !argv[7] || !argv[8]) {
        string_log(1, "Incorrect Usage. Some argument is null\n"
                "Usage: ./lisod <HTTP port> <HTTPS port> <string_log file> "
                "<lock file> <www folder> <CGI script path> <private key file>"
                " <certificate file> \n");

        return EXIT_FAILURE;
    }

    state.port = atoi(argv[1]);
    state.secure_port = atoi(argv[2]);
    state.full = FD_SETSIZE - 1;
    strcpy(state.log_file, argv[3]);
    strcpy(state.lock_file, argv[4]);
    strcpy(state.www_path, argv[5]);
    strcpy(state.cgi_path, argv[6]);
    strcpy(state.key_path, argv[7]);
    strcpy(state.cert_path, argv[8]);

    init_log(state.log_file);

    if (!init_ssl(state.key_path, state.cert_path)) {
        fprintf(stderr, "Error initiating SSL.\n");
        return EXIT_FAILURE;

    }

//    daemonize(state.lock_file);

    string_log(1, "----- Lisod WebServer -----\n");

    /* all networked programs must create a socket */
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        string_log(0, "Failed creating socket.\n");
        return EXIT_FAILURE;
    }

    int optval;
    optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

    state.sock = sock;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(state.port);

    addr.sin_addr.s_addr = INADDR_ANY;

    /* servers bind sockets to ports---notify the OS they accept connections */
    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr))) {
        close_socket(sock);
        string_log(0, "Failed binding socket.\n");
        return EXIT_FAILURE;
    }


    if (listen(sock, 5)) {
        close_socket(sock);
        string_log(0, "Error listening on socket.\n");
        return EXIT_FAILURE;
    }

    if (!(secure_sock = setup_secure_socket(&addr, state.secure_port))) {
        fprintf(stderr, "Error creating secure socket.\n");
        return EXIT_FAILURE;
    }

    int optval1;
    optval1 = 1;
    setsockopt(secure_sock, SOL_SOCKET, SO_REUSEADDR, &optval1, sizeof optval1);

    state.secure_sock = secure_sock;

    // Init the client_set
    struct client_set clients;

    init_client_set(&clients, &state);

    /* finally, loop waiting for input and then write it back */
    while (1) {

        clients.ready_set = clients.read_set;

        if ((clients.rfds = select(clients.nfds + 1, &(clients.ready_set), NULL,
                                   NULL, NULL)) < 0) {
            fprintf(stderr, "%d\n", errno);
            close(sock);
            string_log(0, "Error using select.\n");
            return EXIT_FAILURE;
        }

        if (FD_ISSET(sock, &(clients.ready_set))) {
            cli_size = sizeof(cli_addr);

            // Connecting to an unsecured client
            if ((client_sock = accept(sock, (struct sockaddr *) &cli_addr,
                                      &cli_size)) > 0) {
                if (isfull(state, &clients)) {
                    int id;
                    id = add_client(client_sock, &clients, 0, NULL);
                    string_log(0,
                               "Too many clients, cannot add client %d "
                                       "sending 503\n",
                               id);
                    send_error(id, &clients, 503);
                    close_client(id, &clients);
                } else {
                    add_client(client_sock, &clients, 0, NULL);
                }
            } else {
                close(sock);
                string_log(0, "Error accepting connection from normal "
                        "socket.\n");
                return EXIT_FAILURE;
            }
        }

        if (FD_ISSET(secure_sock, &(clients.ready_set))) {
            // Connecting to a secured client
            if ((client_sock = accept(secure_sock,
                                      (struct sockaddr *) &cli_addr,
                                      &cli_size)) > 0) {
                if (isfull(state, &clients)) {
                    int id;
                    id = add_client(client_sock, &clients, 1, NULL);
                    string_log(0,
                               "Too many clients, cannot add client %d "
                                       "sending 503\n",
                               id);
                    send_error(id, &clients, 503);
                    close_client(id, &clients);
                } else {
                    SSL *client_context;
                    if ((client_context = wrap_client_socket(client_sock,
                                                             secure_sock)) !=
                        NULL) {
                        add_client(client_sock, &clients, 1, client_context);

                    }

                }
            } else {
                close(secure_sock);
                string_log(0, "Error accepting connection from secure "
                        "socket.\n");
                return EXIT_FAILURE;
            }
        }


        process_clients(&clients, &state);

    }

    close_socket(sock);
    close_socket(secure_sock);
    close_log();

    return EXIT_SUCCESS;
}
