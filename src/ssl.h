#include <stdio.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>

/* init_ssl
 *  Initiates the server's ssl that is used by server to encrypt requests
 *  and responses. This creates a new ssl context, and registers the private
 *  key as well as the certificates.
 *
 *  Parameters:
 *      key  - contains the ssl private key path
 *      cert - contains the ssl certificate path
 */
int init_ssl(char *key, char *cert);

/* setup_secure_socket
 *  Creates a secure socket given the secure port. This will bind the port
 *  and start listening for secure connections at that port.
 *
 *  Parameters:
 *      addr        - address object containing all the options, does
 *                      not need to contain the port.
 *      secure_port - contains the port number specified by the input.
 */
int setup_secure_socket(struct sockaddr_in *addr, int secure_port);

/* wrap_client_socket
 *  Creates an SSL *client_context object and returns it. This is responsible
 *  for setting the file descriptor of the client to the client_context.
 *  Returns null if an error happens.
 *
 *  Parameters:
 *      client_sock - file descriptor of the client
 *      sock        - listening socket of the server (must be secure)
 */
SSL *wrap_client_socket(int client_sock, int sock);