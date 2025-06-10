#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>

#define MAX_KNOWN_PORTS 128
#define MAX_LINE_LENGTH 512
#define METRICS_BUFFER_SIZE (4096 * 10)

// Global configuration struct
struct ExporterConfig {
    int show_established_listening;
    int aggregate_ports;
    unsigned short known_ports[MAX_KNOWN_PORTS];
    int known_ports_count;
} config = {0};

// Helper function to check if a port is in the "known" list
int is_port_known(unsigned short port) {
    for (int i = 0; i < config.known_ports_count; i++) {
        if (config.known_ports[i] == port) {
            return 1;
        }
    }
    return 0;
}

// Function to generate metrics into a buffer
void generate_metrics(char* buffer, size_t buffer_size) {
    // Start with the Prometheus metric help and type headers
    snprintf(buffer, buffer_size,
             "# HELP netstat_connections_total Total number of connections.\n"
             "# TYPE netstat_connections_total gauge\n");

    FILE* fp = fopen("/proc/net/tcp", "r");
    if (fp == NULL) {
        perror("Failed to open /proc/net/tcp");
        return;
    }

    char line[MAX_LINE_LENGTH];
    fgets(line, sizeof(line), fp); // Skip header line

    while (fgets(line, sizeof(line), fp)) {
        unsigned int local_ip_hex, remote_ip_hex, state_hex;
        int local_port, remote_port;
        
        int items = sscanf(line, "%*d: %x:%x %x:%x %x",
               &local_ip_hex, &local_port, &remote_ip_hex, &remote_port, &state_hex);

        if (items < 5) continue;

        const char* state_str;
        switch (state_hex) {
            case 0x01: state_str = "ESTABLISHED"; break;
            case 0x0A: state_str = "LISTEN"; break;
            default:   state_str = "OTHER"; break;
        }
        
        if (config.show_established_listening && (strcmp(state_str, "ESTABLISHED") != 0 && strcmp(state_str, "LISTEN") != 0)) {
            continue;
        }

        char local_ip_str[INET_ADDRSTRLEN];
        char remote_ip_str[INET_ADDRSTRLEN];
        struct in_addr local_in_addr = {.s_addr = local_ip_hex};
        struct in_addr remote_in_addr = {.s_addr = remote_ip_hex};
        
        inet_ntop(AF_INET, &local_in_addr, local_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &remote_in_addr, remote_ip_str, INET_ADDRSTRLEN);

        char local_port_label[32];
        char remote_port_label[32];

        if (config.aggregate_ports && !is_port_known(local_port)) {
            strcpy(local_port_label, "ephemeral");
        } else {
            snprintf(local_port_label, sizeof(local_port_label), "%d", local_port);
        }

        if (config.aggregate_ports && !is_port_known(remote_port)) {
            strcpy(remote_port_label, "ephemeral");
        } else {
            snprintf(remote_port_label, sizeof(remote_port_label), "%d", remote_port);
        }

        char metric_line[MAX_LINE_LENGTH];
        snprintf(metric_line, sizeof(metric_line),
                 "netstat_connections_total{state=\"%s\",src_ip=\"%s\",src_port=\"%s\",dst_ip=\"%s\",dst_port=\"%s\"} 1\n",
                 state_str, local_ip_str, local_port_label, remote_ip_str, remote_port_label);
        
        // Append to buffer, checking for space
        if (strlen(buffer) + strlen(metric_line) < buffer_size - 1) {
            strcat(buffer, metric_line);
        }
    }
    fclose(fp);
}

// Function to parse the config file
void parse_config_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Could not open config file, proceeding without filters");
        return;
    }

    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char* key = strtok(line, "=");
        if (!key) continue;
        char* value_str = strtok(NULL, "\n");
        if (!value_str) continue;
        while (isspace((unsigned char)*value_str)) value_str++;
        
        if (strcmp(key, "ports") == 0) {
            char* token = strtok(value_str, "[, ]");
            while (token != NULL) {
                if (config.known_ports_count < MAX_KNOWN_PORTS) {
                    config.known_ports[config.known_ports_count++] = (unsigned short)atoi(token);
                }
                token = strtok(NULL, "[, ]");
            }
        } else if (strcmp(key, "endpoints") == 0) {
             char* token = strtok(value_str, "[ \",]");
             while(token != NULL) {
                if (config.known_ports_count < MAX_KNOWN_PORTS) {
                    char* port_str = strrchr(token, ':');
                    if (port_str) {
                       config.known_ports[config.known_ports_count++] = (unsigned short)atoi(port_str + 1);
                    }
                }
                token = strtok(NULL, "[ \",]");
             }
        }
    }
    fclose(file);
}

int main(int argc, char *argv[]) {
    int port = 9102;
    char* config_path = "config.toml";

    static struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"config-path", required_argument, 0, 'c'},
        {"show-established-listening", no_argument, 0, 'e'},
        {"aggregate-ports", no_argument, 0, 'a'},
        {0, 0, 0, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "p:c:ea", long_options, NULL)) != -1) {
        switch (c) {
            case 'p': port = atoi(optarg); break;
            case 'c': config_path = optarg; break;
            case 'e': config.show_established_listening = 1; break;
            case 'a': config.aggregate_ports = 1; break;
            case '?': exit(EXIT_FAILURE);
        }
    }
    
    parse_config_file(config_path);
    
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Starting standalone netstat_exporter on port %d\n", port);

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
            perror("accept");
            continue;
        }

        char request_buffer[1024] = {0};
        read(new_socket, request_buffer, 1023);

        if (strncmp(request_buffer, "GET /metrics", 12) == 0) {
            char* metrics_buffer = malloc(METRICS_BUFFER_SIZE);
            if (!metrics_buffer) {
                perror("Failed to allocate metrics buffer");
                close(new_socket);
                continue;
            }
            generate_metrics(metrics_buffer, METRICS_BUFFER_SIZE);

            char http_header[256];
            snprintf(http_header, sizeof(http_header),
                     "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: %zu\r\n\r\n",
                     strlen(metrics_buffer));

            write(new_socket, http_header, strlen(http_header));
            write(new_socket, metrics_buffer, strlen(metrics_buffer));
            free(metrics_buffer);
        } else {
            const char* not_found_response = "HTTP/1.1 404 Not Found\r\n\r\n";
            write(new_socket, not_found_response, strlen(not_found_response));
        }
        close(new_socket);
    }

    return 0;
}

