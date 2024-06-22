#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define SERVER_ADDRESS "127.0.0.1"
#define SERVER_PORT 12345
#define KEY_SIZE 16

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

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[1024];
    char option[2];
    unsigned char key[KEY_SIZE] = "mySimpleSharedKey";

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_ADDRESS, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    printf("Connected to the bank server\n");
    printf("Do you want to (1) Register or (2) Login? (Enter 1 or 2)\n");
    fgets(option, 2, stdin);

    if (strcmp(option, "1") == 0) {
        while (1) {
            char username[256], password[256];
            printf("Enter username for registration:\n");
            fgets(username, 256, stdin);
            printf("Enter password for registration:\n");
            fgets(password, 256, stdin);

            send(sockfd, "REGISTER", strlen("REGISTER"), 0);
            send(sockfd, username, strlen(username), 0);
            send(sockfd, password, strlen(password), 0);

            recv(sockfd, buffer, sizeof(buffer), 0);
            printf("%s\n", buffer);

            if (strncmp(buffer, "ERROR", 5) != 0) {
                break;
            }
        }
    } else if (strcmp(option, "2") == 0) {
        char username[256], password[256];
        printf("Enter username for login:\n");
        fgets(username, 256, stdin);
        printf("Enter password for login:\n");
        fgets(password, 256, stdin);

        send(sockfd, "LOGIN", strlen("LOGIN"), 0);
        send(sockfd, username, strlen(username), 0);
        send(sockfd, password, strlen(password), 0);

        recv(sockfd, buffer, sizeof(buffer), 0);
        printf("%s\n", buffer);

        if (strcmp(buffer, "LOGGED IN") == 0) {
            char nonce_C[KEY_SIZE];
            char encrypted_nonce_C[KEY_SIZE];
            char encrypted_nonce_S[KEY_SIZE];
            char decrypted_nonce_S[KEY_SIZE];

            generate_nonce(nonce_C, KEY_SIZE);
            encrypt((unsigned char *)nonce_C, key, (unsigned char *)encrypted_nonce_C);

            send(sockfd, encrypted_nonce_C, KEY_SIZE, 0);
            recv(sockfd, encrypted_nonce_S, KEY_SIZE, 0);
            decrypt((unsigned char *)encrypted_nonce_S, key, (unsigned char *)decrypted_nonce_S);

            printf("Key distribution protocol complete.\n");
        }
    }

    close(sockfd);
    return 0;
}
