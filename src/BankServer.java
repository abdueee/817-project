#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define PORT 12345
#define KEY_SIZE 16

typedef struct {
    int sock;
    struct sockaddr_in address;
    int addr_len;
} connection_t;

typedef struct {
    char username[256];
    char password[256];
} user_t;

user_t userDatabase[100];
int userCount = 0;

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext) {
    AES_KEY enc_key;
    AES_set_encrypt_key(key, 128, &enc_key);
    AES_encrypt(plaintext, ciphertext, &enc_key);
}

void decrypt(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext) {
    AES_KEY dec_key;
    AES_set_decrypt_key(key, 128, &dec_key);
    AES_decrypt(ciphertext, plaintext, &dec_key);
}

void generate_nonce(char *nonce, size_t length) {
    if (!RAND_bytes((unsigned char *)nonce, length)) {
        handleErrors();
    }
}

void *client_handler(void *ptr) {
    connection_t *conn;
    char buffer[1024];
    unsigned char key[KEY_SIZE] = "mySimpleSharedKey";

    if (!ptr) pthread_exit(0); 
    conn = (connection_t *)ptr;

    while (1) {
        int len = recv(conn->sock, buffer, sizeof(buffer), 0);
        if (len <= 0) break;

        buffer[len] = '\0';

        if (strcmp(buffer, "REGISTER") == 0) {
            char username[256], password[256];
            recv(conn->sock, username, sizeof(username), 0);
            recv(conn->sock, password, sizeof(password), 0);

            int user_exists = 0;
            for (int i = 0; i < userCount; i++) {
                if (strcmp(userDatabase[i].username, username) == 0) {
                    user_exists = 1;
                    break;
                }
            }

            if (user_exists) {
                send(conn->sock, "ERROR: User already exists. Please try a different username.", 64, 0);
            } else {
                strcpy(userDatabase[userCount].username, username);
                strcpy(userDatabase[userCount].password, password);
                userCount++;
                send(conn->sock, "SUCCESS: User registered successfully.", 38, 0);
            }
        } else if (strcmp(buffer, "LOGIN") == 0) {
            char username[256], password[256];
            recv(conn->sock, username, sizeof(username), 0);
            recv(conn->sock, password, sizeof(password), 0);

            int loggedIn = 0;
            for (int i = 0; i < userCount; i++) {
                if (strcmp(userDatabase[i].username, username) == 0 && strcmp(userDatabase[i].password, password) == 0) {
                    loggedIn = 1;
                    break;
                }
            }

            if (loggedIn) {
                send(conn->sock, "LOGGED IN", 9, 0);
                char nonce_S[KEY_SIZE];
                char encrypted_nonce_S[KEY_SIZE];
                char encrypted_nonce_C[KEY_SIZE];
                char decrypted_nonce_C[KEY_SIZE];

                generate_nonce(nonce_S, KEY_SIZE);
                encrypt((unsigned char *)nonce_S, key, (unsigned char *)encrypted_nonce_S);
                send(conn->sock, encrypted_nonce_S, KEY_SIZE, 0);
                recv(conn->sock, encrypted_nonce_C, KEY_SIZE, 0);
                decrypt((unsigned char *)encrypted_nonce_C, key, (unsigned char *)decrypted_nonce_C);

                printf("Key distribution protocol complete.\n");
            } else {
                send(conn->sock, "LOGIN FAILED", 13, 0);
            }
        } else if (strcmp(buffer, "QUIT") == 0) {
            break;
        }
    }

    close(conn->sock);
    free(conn);
    pthread_exit(0);
}

int main() {
    int sockfd, newsockfd;
    struct sockaddr_in server_addr, client_addr;
    connection_t *connection;
    pthread_t thread;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, 5) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Bank Server is listening on port %d\n", PORT);

    while (1) {
        newsockfd = accept(sockfd, (struct sockaddr *)&client_addr, (socklen_t*)&client_addr);
        if (newsockfd <= 0) {
            perror("Accept failed");
            continue;
        }

        connection = (connection_t *)malloc(sizeof(connection_t));
        connection->sock = newsockfd;
        connection->address = client_addr;
        connection->addr_len = sizeof(client_addr);

        pthread_create(&thread, 0, client_handler, (void *)connection);
        pthread_detach(thread);
    }

    close(sockfd);
    return 0;
}
