#define MAX_PATH_SIZE 1024

struct server_state {
    int port;
    int sock;
    int secure_port;
    int secure_sock;
    int full;
    char log_file[MAX_PATH_SIZE];
    char lock_file[MAX_PATH_SIZE];
    char www_path[MAX_PATH_SIZE];
    char cgi_path[MAX_PATH_SIZE];
    char key_path[MAX_PATH_SIZE];
    char cert_path[MAX_PATH_SIZE];
};