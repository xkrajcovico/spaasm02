#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <pwd.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/select.h>

#define DEFAULT_PORT 55555
#define DEFAULT_IP "127.0.0.1"
#define MAX_LINE 4096
#define TIME_FORMAT "%H:%M:%S"
#define MAX_ARGS 64
#define MAX_CONNECTIONS 10
#define MAX_PORTS 10

// Structure to track active client connections
typedef struct {
    int fd;                     // File descriptor for the connection
    struct sockaddr_in addr;    // Client address information
    time_t connect_time;        // When the connection was established
    pid_t pid;                  // Process ID handling this connection
} Connection;

// Structure to track listening ports
typedef struct {
    int port;    // Port number
    int fd;      // File descriptor for the listening socket
    int active;  // Whether this port is active
} PortInfo;

Connection connections[MAX_CONNECTIONS];  // Array of active connections
PortInfo ports[MAX_PORTS];               // Array of listening ports
int num_connections = 0;                 // Current number of connections
int num_ports = 0;                       // Current number of listening ports
int running = 1;                         // Server running flag

// Function prototypes
void handle_client(int client_fd);
void run_server(char *ip);
void run_client(int port, char *ip);
void cleanup(int sig);
char* execute_command(const char* cmd);
void get_prompt(char* prompt, size_t size);
int safe_write(int fd, const void* buf, size_t len);
int safe_read(int fd, void* buf, size_t len);
void parse_command(char* cmd, char** args);
void trim_whitespace(char* str);
void strip_comments(char* cmd);
void add_connection(int fd, struct sockaddr_in addr, pid_t pid);
void remove_connection(int fd);
void print_connections();
void handle_server_command(char* cmd);
int listen_port(int port);
void close_port(int port);
void abort_connection(int client_fd);
void process_server_input();
void close_all_ports();

// Clean up resources and exit
void cleanup(int sig) {
    running = 0;
    close_all_ports();
    exit(0);
}

// Close all listening ports
void close_all_ports() {
    for (int i = 0; i < num_ports; i++) {
        if (ports[i].active) {
            close(ports[i].fd);
            ports[i].active = 0;
            printf("Closed port %d\n", ports[i].port);
        }
    }
    num_ports = 0;
}

// Safe write that handles interrupts and partial writes
int safe_write(int fd, const void* buf, size_t len) {
    size_t total = 0;
    ssize_t n;
    while (total < len) {
        n = write(fd, (const char*)buf + total, len - total);
        if (n <= 0) {
            if (n == -1 && errno == EINTR) continue;
            return -1;
        }
        total += n;
    }
    return total;
}

// Safe read that handles interrupts and partial reads
int safe_read(int fd, void* buf, size_t len) {
    size_t total = 0;
    ssize_t n;
    while (total < len) {
        n = read(fd, (char*)buf + total, len - total);
        if (n <= 0) {
            if (n == -1 && errno == EINTR) continue;
            return -1;
        }
        total += n;
    }
    return total;
}

// Generate shell prompt with timestamp, user and hostname
void get_prompt(char* prompt, size_t size) {
    time_t now;
    time(&now);
    char time_str[20];
    strftime(time_str, sizeof(time_str), TIME_FORMAT, localtime(&now));
    
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, HOST_NAME_MAX);
    
    char* username = getpwuid(getuid())->pw_name;
    
    snprintf(prompt, size, "%s %s@%s# ", time_str, username, hostname);
}

// Trim whitespace from both ends of a string
void trim_whitespace(char* str) {
    char* end;
    while (*str == ' ') str++;
    end = str + strlen(str) - 1;
    while (end > str && *end == ' ') end--;
    *(end + 1) = '\0';
}

// Remove comments (everything after #)
void strip_comments(char* cmd) {
    char* comment = strchr(cmd, '#');
    if (comment != NULL) {
        *comment = '\0';
        trim_whitespace(cmd);
    }
}

// Parse command into arguments
void parse_command(char* cmd, char** args) {
    int i = 0;
    char* token = strtok(cmd, " ");
    while (token != NULL && i < MAX_ARGS - 1) {
        args[i++] = token;
        token = strtok(NULL, " ");
    }
    args[i] = NULL;
}

// Add a new connection to tracking array
void add_connection(int fd, struct sockaddr_in addr, pid_t pid) {
    if (num_connections < MAX_CONNECTIONS) {
        connections[num_connections].fd = fd;
        connections[num_connections].addr = addr;
        connections[num_connections].connect_time = time(NULL);
        connections[num_connections].pid = pid;
        num_connections++;
    }
}

// Remove a connection from tracking array
void remove_connection(int fd) {
    for (int i = 0; i < num_connections; i++) {
        if (connections[i].fd == fd) {
            kill(connections[i].pid, SIGTERM);  // Terminate client process
            waitpid(connections[i].pid, NULL, 0);
            
            // Shift remaining connections down
            for (int j = i; j < num_connections - 1; j++) {
                connections[j] = connections[j + 1];
            }
            num_connections--;
            break;
        }
    }
}

// Print all active connections
void print_connections() {
    printf("Active connections:\n");
    printf("FD\tIP Address\t\tPort\tConnected Since\n");
    for (int i = 0; i < num_connections; i++) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &connections[i].addr.sin_addr, ip, INET_ADDRSTRLEN);
        printf("%d\t%s\t%d\t%s", connections[i].fd, ip,
               ntohs(connections[i].addr.sin_port),
               ctime(&connections[i].connect_time));
    }
}
// Start listening on a new port
int listen_port(int port) {
    if (num_ports >= MAX_PORTS) {
        printf("Maximum number of ports reached\n");
        return -1;
    }

    // Check if port is already listening
    for (int i = 0; i < num_ports; i++) {
        if (ports[i].port == port) {
            printf("Port %d is already listening\n", port);
            return -1;
        }
    }

    // Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        return -1;
    }

    // Set socket options
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind socket to port
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        close(sockfd);
        return -1;
    }

    // Start listening
    if (listen(sockfd, 5) < 0) {
        perror("listen failed");
        close(sockfd);
        return -1;
    }

    // Add to ports array
    ports[num_ports].port = port;
    ports[num_ports].fd = sockfd;
    ports[num_ports].active = 1;
    num_ports++;

    printf("Listening on port %d\n", port);
    return sockfd;
}

// Close a listening port
void close_port(int port) {
    for (int i = 0; i < num_ports; i++) {
        if (ports[i].port == port && ports[i].active) {
            close(ports[i].fd);
            ports[i].active = 0;
            
            // Shift remaining ports down
            for (int j = i; j < num_ports - 1; j++) {
                ports[j] = ports[j + 1];
            }
            num_ports--;
            
            printf("Closed port %d\n", port);
            return;
        }
    }
    printf("Port %d not found or not active\n", port);
}

// Abort an active connection
void abort_connection(int client_fd) {
    for (int i = 0; i < num_connections; i++) {
        if (connections[i].fd == client_fd) {
            close(client_fd);
            remove_connection(client_fd);
            printf("Connection %d aborted\n", client_fd);
            return;
        }
    }
    printf("Connection FD %d not found\n", client_fd);
}

// Process input from server console
void process_server_input() {
    char input_buffer[MAX_LINE];
    if (fgets(input_buffer, MAX_LINE, stdin)) {
        input_buffer[strcspn(input_buffer, "\n")] = '\0';
        handle_server_command(input_buffer);
    }
}

// Handle commands entered in server console
void handle_server_command(char* cmd) {
    char* args[MAX_ARGS];
    parse_command(cmd, args);

    if (args[0] == NULL) return;

    if (strcmp(args[0], "stat") == 0) {
        print_connections();
    } else if (strcmp(args[0], "listen") == 0 && args[1] != NULL) {
        listen_port(atoi(args[1]));
    } else if (strcmp(args[0], "close") == 0 && args[1] != NULL) {
        close_port(atoi(args[1]));
    } else if (strcmp(args[0], "abort") == 0 && args[1] != NULL) {
        abort_connection(atoi(args[1]));
    } else if (strcmp(args[0], "halt") == 0) {
        printf("Server shutdown initiated\n");
        cleanup(0);
    } else {
        printf("Unknown server command: %s\n", args[0]);
    }
}

// Execute a shell command and return output
char* execute_command(const char* cmd_input) {
    char* result = malloc(1);
    result[0] = '\0';
    size_t result_len = 0;

    char cmd[MAX_LINE];
    strcpy(cmd, cmd_input);

    strip_comments(cmd);

    // Handle cd command specially
    if (strncmp(cmd, "cd ", 3) == 0) {
        char* path = cmd + 3;
        trim_whitespace(path);
        if (chdir(path)) {
            char error[256];
            snprintf(error, sizeof(error), "cd: %s: %s\n", path, strerror(errno));
            size_t error_len = strlen(error);
            result = realloc(result, error_len + 1);
            strcpy(result, error);
            return result;
        } else {
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd))) {
                strcat(cwd, "\n");
                result = realloc(result, strlen(cwd) + 1);
                strcpy(result, cwd);
            } else {
                result = realloc(result, 2);
                strcpy(result, "\n");
            }
            return result;
        }
    }

    // Split multiple commands separated by ;
    char* commands[MAX_ARGS];
    int cmd_count = 0;
    char* saveptr;
    char* token = strtok_r(cmd, ";", &saveptr);

    while (token != NULL && cmd_count < MAX_ARGS - 1) {
        trim_whitespace(token);
        if (*token != '\0') {
            commands[cmd_count++] = token;
        }
        token = strtok_r(NULL, ";", &saveptr);
    }

    // Execute each command
    for (int i = 0; i < cmd_count; i++) {
        char* current_cmd = strdup(commands[i]);
        char* output_file = NULL;
        char* input_file = NULL;

        // Handle output redirection
        char* output_redir = strrchr(current_cmd, '>');
        if (output_redir != NULL) {
            *output_redir = '\0';
            output_file = output_redir + 1;
            trim_whitespace(output_file);
            trim_whitespace(current_cmd);
        }

        // Handle input redirection
        char* input_redir = strchr(current_cmd, '<');
        if (input_redir != NULL) {
            *input_redir = '\0';
            input_file = input_redir + 1;
            trim_whitespace(input_file);
            trim_whitespace(current_cmd);
        }

        // Split into piped commands if needed
        int pipe_count = 0;
        char* pipe_cmds[MAX_ARGS];
        char* pipe_saveptr;
        char* pipe_token = strtok_r(current_cmd, "|", &pipe_saveptr);
        while (pipe_token != NULL && pipe_count < MAX_ARGS - 1) {
            trim_whitespace(pipe_token);
            pipe_cmds[pipe_count++] = pipe_token;
            pipe_token = strtok_r(NULL, "|", &pipe_saveptr);
        }

        if (pipe_count > 0) {
            // Handle piped commands
            int prev_pipe[2] = {-1, -1};
            int temp_fd = -1;
            char temp_file[] = "/tmp/spaasm_XXXXXX";

            if (output_file == NULL) {
                temp_fd = mkstemp(temp_file);
                if (temp_fd == -1) {
                    perror("mkstemp");
                    free(current_cmd);
                    continue;
                }
                unlink(temp_file);
            }

            for (int j = 0; j < pipe_count; j++) {
                int next_pipe[2] = {-1, -1};
                if (j < pipe_count - 1) {
                    if (pipe(next_pipe) == -1) {
                        perror("pipe");
                        break;
                    }
                }

                pid_t pid = fork();
                if (pid == -1) {
                    perror("fork");
                    break;
                }

                if (pid == 0) { // Child process
                    if (j == 0 && input_file != NULL) {
                        int fd = open(input_file, O_RDONLY);
                        if (fd == -1) {
                            perror("open input");
                            exit(EXIT_FAILURE);
                        }
                        dup2(fd, STDIN_FILENO);
                        close(fd);
                    } else if (j > 0) {
                        dup2(prev_pipe[0], STDIN_FILENO);
                        close(prev_pipe[0]);
                        close(prev_pipe[1]);
                    }

                    if (j == pipe_count - 1) {
                        if (output_file != NULL) {
                            int fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                            if (fd == -1) {
                                perror("open output");
                                exit(EXIT_FAILURE);
                            }
                            dup2(fd, STDOUT_FILENO);
                            close(fd);
                        } else {
                            dup2(temp_fd, STDOUT_FILENO);
                            close(temp_fd);
                        }
                    } else {
                        dup2(next_pipe[1], STDOUT_FILENO);
                        close(next_pipe[0]);
                        close(next_pipe[1]);
                    }

                    dup2(STDOUT_FILENO, STDERR_FILENO);

                    char* args[MAX_ARGS];
                    parse_command(pipe_cmds[j], args);
                    execvp(args[0], args);
                    perror("execvp");
                    exit(EXIT_FAILURE);
                } else { // Parent process
                    if (j > 0) {
                        close(prev_pipe[0]);
                        close(prev_pipe[1]);
                    }
                    if (j < pipe_count - 1) {
                        prev_pipe[0] = next_pipe[0];
                        prev_pipe[1] = next_pipe[1];
                    }
                }
            }

            // Wait for all child processes
            for (int j = 0; j < pipe_count; j++) {
                int status;
                wait(&status);
                if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
                    char error[256];
                    snprintf(error, sizeof(error), "Error: command exited with status %d\n", WEXITSTATUS(status));
                    size_t new_len = result_len + strlen(error);
                    result = realloc(result, new_len + 1);
                    strcat(result + result_len, error);
                    result_len = new_len;
                }
            }

            // Read output if no output file specified
            if (output_file == NULL && temp_fd != -1) {
                lseek(temp_fd, 0, SEEK_SET);
                char buffer[MAX_LINE];
                ssize_t bytes;
                while ((bytes = read(temp_fd, buffer, sizeof(buffer) - 1)) > 0) {
                    buffer[bytes] = '\0';
                    size_t new_len = result_len + bytes;
                    result = realloc(result, new_len + 1);
                    strcat(result + result_len, buffer);
                    result_len = new_len;
                }
                close(temp_fd);
            }
        } else {
            // Handle simple command (no pipes)
            int temp_fd = -1;
            char temp_file[] = "/tmp/spaasm_XXXXXX";

            if (output_file == NULL) {
                temp_fd = mkstemp(temp_file);
                if (temp_fd == -1) {
                    perror("mkstemp");
                    free(current_cmd);
                    continue;
                }
                unlink(temp_file);
            }

            pid_t pid = fork();
            if (pid == 0) { // Child process
                if (input_file != NULL) {
                    int fd = open(input_file, O_RDONLY);
                    if (fd == -1) {
                        perror("open input");
                        exit(EXIT_FAILURE);
                    }
                    dup2(fd, STDIN_FILENO);
                    close(fd);
                }

                if (output_file != NULL) {
                    int fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (fd == -1) {
                        perror("open output");
                        exit(EXIT_FAILURE);
                    }
                    dup2(fd, STDOUT_FILENO);
                    close(fd);
                } else {
                    dup2(temp_fd, STDOUT_FILENO);
                    close(temp_fd);
                }

                dup2(STDOUT_FILENO, STDERR_FILENO);

                char* args[MAX_ARGS];
                parse_command(current_cmd, args);
                execvp(args[0], args);
                perror("execvp");
                exit(EXIT_FAILURE);
            } else { // Parent process
                int status;
                waitpid(pid, &status, 0);
                if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
                    char error[256];
                    snprintf(error, sizeof(error), "Error: command exited with status %d\n", WEXITSTATUS(status));
                    size_t new_len = result_len + strlen(error);
                    result = realloc(result, new_len + 1);
                    strcat(result + result_len, error);
                    result_len = new_len;
                }

                // Read output if no output file specified
                if (output_file == NULL && temp_fd != -1) {
                    lseek(temp_fd, 0, SEEK_SET);
                    char buffer[MAX_LINE];
                    ssize_t bytes;
                    while ((bytes = read(temp_fd, buffer, sizeof(buffer) - 1)) > 0) {
                        buffer[bytes] = '\0';
                        size_t new_len = result_len + bytes;
                        result = realloc(result, new_len + 1);
                        strcat(result + result_len, buffer);
                        result_len = new_len;
                    }
                    close(temp_fd);
                }
            }
        }
        free(current_cmd);
    }

    return result;
}

// Handle communication with a connected client
void handle_client(int client_fd) {
    char buffer[MAX_LINE];
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(client_fd, (struct sockaddr*)&addr, &addr_len);
    pid_t pid = getpid();
    add_connection(client_fd, addr, pid);
    printf("Client connected from %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    while (1) {
        ssize_t bytes = read(client_fd, buffer, MAX_LINE - 1);
        if (bytes <= 0) {
            if (bytes == 0) printf("Client disconnected\n");
            break;
        }
        buffer[bytes] = '\0';

        // Handle quit command
        if (strcmp(buffer, "quit") == 0) {
            uint32_t len = htonl(7);
            safe_write(client_fd, &len, sizeof(len));
            safe_write(client_fd, "Goodbye", 7);
            break;
        }

        // Handle stat command
        if (strcmp(buffer, "stat") == 0) {
            char stat_info[MAX_LINE * 2] = {0};
            strcat(stat_info, "Active connections:\n");
            strcat(stat_info, "FD\tIP Address\t\tPort\tConnected Since\n");
            for (int i = 0; i < num_connections; i++) {
                char line[256];
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &connections[i].addr.sin_addr, ip, INET_ADDRSTRLEN);
                snprintf(line, sizeof(line), "%d\t%s\t%d\t%s", connections[i].fd, ip,
                       ntohs(connections[i].addr.sin_port),
                       ctime(&connections[i].connect_time));
                strcat(stat_info, line);
            }
            uint32_t len = strlen(stat_info);
            uint32_t net_len = htonl(len);
            safe_write(client_fd, &net_len, sizeof(net_len));
            safe_write(client_fd, stat_info, len);
            continue;
        }

        // Handle halt command
        if (strcmp(buffer, "halt") == 0) {
            running = 0;
            char* msg = "Server shutdown initiated\n";
            uint32_t len = strlen(msg);
            uint32_t net_len = htonl(len);
            safe_write(client_fd, &net_len, sizeof(net_len));
            safe_write(client_fd, msg, len);
            close_all_ports();
            exit(0);
        }

        // Execute command and send back results
        char* result = execute_command(buffer);
        uint32_t result_len = strlen(result);
        uint32_t net_len = htonl(result_len);
        safe_write(client_fd, &net_len, sizeof(net_len));
        safe_write(client_fd, result, result_len);
        free(result);
    }

    remove_connection(client_fd);
    close(client_fd);
}

// Main server loop
void run_server(char *ip) {
    signal(SIGTERM, cleanup);
    signal(SIGINT, cleanup);

    printf("Server ready. Use 'listen PORT' to start listening on a port\n");
    printf("Available commands: stat, listen PORT, close PORT, abort FD, halt\n");

    fd_set read_fds;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000; // 100ms timeout

    while (running) {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);

        int max_fd = STDIN_FILENO;
        for (int i = 0; i < num_ports; i++) {
            if (ports[i].active) {
                FD_SET(ports[i].fd, &read_fds);
                if (ports[i].fd > max_fd) max_fd = ports[i].fd;
            }
        }

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
        if (activity < 0) {
            if (errno == EINTR) continue;
            perror("select error");
            continue;
        }

        // Handle server console input
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            process_server_input();
        }

        // Check for new connections
        for (int i = 0; i < num_ports; i++) {
            if (ports[i].active && FD_ISSET(ports[i].fd, &read_fds)) {
                int client_fd = accept(ports[i].fd, NULL, NULL);
                if (client_fd < 0) {
                    if (errno == EINTR) continue;
                    perror("accept failed");
                    continue;
                }

                // Fork to handle new client
                pid_t pid = fork();
                if (pid == 0) { // Child
                    close_all_ports(); // Close all listening ports in child
                    handle_client(client_fd);
                    exit(0);
                } else if (pid > 0) { // Parent
                    struct sockaddr_in addr;
                    socklen_t addr_len = sizeof(addr);
                    getpeername(client_fd, (struct sockaddr*)&addr, &addr_len);
                    add_connection(client_fd, addr, pid);
                } else {
                    perror("fork failed");
                    close(client_fd);
                }
            }
        }

        // Clean up zombie processes
        while (waitpid(-1, NULL, WNOHANG) > 0);
    }
}

// Client main function
void run_client(int port, char *ip) {
    int client_fd;
    struct sockaddr_in server_addr;

    // Create socket
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        perror("socket creation failed");
        exit(1);
    }

    // Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("invalid IP address");
        exit(1);
    }

    // Connect to server
    if (connect(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect failed");
        exit(1);
    }

    printf("Connected to %s:%d\n", ip, port);

    char buffer[MAX_LINE];
    char prompt[256];

    // Main client loop
    while (1) {
        get_prompt(prompt, sizeof(prompt));
        printf("%s", prompt);
        fflush(stdout);

        if (!fgets(buffer, MAX_LINE, stdin)) break;
        buffer[strcspn(buffer, "\n")] = '\0';

        if (strlen(buffer) == 0) continue;

        // Send command to server
        if (safe_write(client_fd, buffer, strlen(buffer)) <= 0) break;

        if (strcmp(buffer, "quit") == 0) break;

        // Read response length
        uint32_t net_len;
        if (safe_read(client_fd, (char*)&net_len, sizeof(net_len)) <= 0) break;
        uint32_t len = ntohl(net_len);
        
        // Read response data
        if (len > 0) {
            char* response = malloc(len + 1);
            if (safe_read(client_fd, response, len) <= 0) {
                free(response);
                break;
            }
            response[len] = '\0';
            printf("%s", response);
            free(response);
        }
    }

    close(client_fd);
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    char *ip = DEFAULT_IP;
    int server_mode = 0;
    int client_mode = 0;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            printf("Remote Command Execution Tool\n");
            printf("Usage: %s [-s (server) | -c (client)] [-p port] [-i ip]\n\n", argv[0]);
            printf("Options:\n");
            printf("  -s         Run in server mode\n");
            printf("  -c         Run in client mode\n");
            printf("  -p PORT    Specify port number (default: %d)\n", DEFAULT_PORT);
            printf("  -i IP      Specify IP address (default: %s)\n", DEFAULT_IP);
            printf("  -h         Show this help message\n\n");
            printf("Examples:\n");
            printf("  Start server: %s -s\n", argv[0]);
            printf("  Connect client: %s -c -i 192.168.1.100 -p 55555\n", argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-s") == 0) {
            server_mode = 1;
        } else if (strcmp(argv[i], "-c") == 0) {
            client_mode = 1;
        } else if (strcmp(argv[i], "-p") == 0 && i+1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-i") == 0 && i+1 < argc) {
            ip = argv[++i];
        }
    }

    // Validate arguments
    if (server_mode && client_mode) {
        fprintf(stderr, "Error: Cannot be both server and client\n");
        return 1;
    }

    if (!server_mode && !client_mode) {
        fprintf(stderr, "Error: Must specify -s or -c\n");
        return 1;
    }

    // Start in appropriate mode
    if (server_mode) {
        run_server(ip);
    } else {
        run_client(port, ip);
    }

    return 0;
}
