#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// cleanup function, self explanatory
void CleanUp(RSA *rsa, BIGNUM *bn, BIO *pub, char *pub_key) {
    if (rsa) RSA_free(rsa);
    if (bn) BN_free(bn);
    if (pub) BIO_free(pub);
    if (pub_key) free(pub_key);
}

// generates a public and private key pair using OPENSSL api with size 2048 bits
int GenerateKey(RSA **rsa, BIGNUM **bn, char **pubKey, size_t *pubKeyLen){
    *bn = BN_new();
    if (!*bn) {
        fprintf(stderr, "BN_new failed\n");
        return -1;
    }
    if (BN_set_word(*bn, RSA_F4) != 1) {
        fprintf(stderr, "BN_set_word failed\n");
        BN_free(*bn);
        return -1;
    }
    *rsa = RSA_new();
    if (!*rsa) {
        fprintf(stderr, "RSA_new failed\n");
        BN_free(*bn);
        return -1;
    }
    if (RSA_generate_key_ex(*rsa, 2048, *bn, NULL) != 1){
        fprintf(stderr, "Key generation failed\n");
        RSA_free(*rsa);
        BN_free(*bn);
        return -1;
    }
    printf("Key pair generated...\n");

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        fprintf(stderr, "BIO_new failed\n");
        RSA_free(*rsa);
        BN_free(*bn);
        return -1;
    }
    if (!PEM_write_bio_RSAPublicKey(bio, *rsa)) { // FIX: pass *rsa, not rsa
        fprintf(stderr, "PEM_write_bio_RSAPublicKey failed\n");
        BIO_free(bio);
        RSA_free(*rsa);
        BN_free(*bn);
        return -1;
    }
    *pubKeyLen = BIO_pending(bio);
    *pubKey = malloc(*pubKeyLen + 1);
    if (!*pubKey) {
        fprintf(stderr, "malloc for pubKey failed\n");
        BIO_free(bio);
        RSA_free(*rsa);
        BN_free(*bn);
        return -1;
    }
    if (BIO_read(bio, *pubKey, *pubKeyLen) != (int)*pubKeyLen) {
        fprintf(stderr, "BIO_read failed\n");
        free(*pubKey);
        BIO_free(bio);
        RSA_free(*rsa);
        BN_free(*bn);
        return -1;
    }
    (*pubKey)[*pubKeyLen] = '\0';
    BIO_free(bio);
    printf("exporting public key....\n");
    return 0;
}

// just a function sending the key via the sockets 
int SendPublicKey(int socketfd, size_t pubKeyLen, char *pubKey){
    uint32_t net_len = htonl(pubKeyLen);
    if(send(socketfd, &net_len, sizeof(net_len), 0) != sizeof(net_len)){
        perror("sending public key length failed");
        return -1;
    } 
    if(send(socketfd, pubKey, pubKeyLen, 0) != (ssize_t)pubKeyLen){
        perror("sending public key failed");
        return -1;
    }  
    printf("public key sent via socket....\n");
    return 0;
}

// function that takes the key value and length and reconstructs the key 
int ExtractPublicKey(int socketfd, RSA **rsa_out) {
    uint32_t net_len;
    if (recv(socketfd, &net_len, sizeof(net_len), MSG_WAITALL) != sizeof(net_len)) {
        perror("recv public key length failed");
        return -1;
    }
    size_t pub_len = ntohl(net_len);

    char *pubKeyExtract = malloc(pub_len + 1);
    if (!pubKeyExtract) {
        fprintf(stderr, "malloc failed\n");
        return -1;
    }
    if (recv(socketfd, pubKeyExtract, pub_len, MSG_WAITALL) != (ssize_t)pub_len) {
        perror("recv public key failed");
        free(pubKeyExtract);
        return -1;
    }
    pubKeyExtract[pub_len] = '\0';

    BIO *bio = BIO_new_mem_buf(pubKeyExtract, pub_len);
    if (!bio) {
        fprintf(stderr, "BIO_new_mem_buf failed\n");
        free(pubKeyExtract);
        return -1;
    }

    RSA *rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    if (!rsa) {
        fprintf(stderr, "PEM_read_bio_RSAPublicKey failed\n");
        ERR_print_errors_fp(stderr);
        BIO_free(bio);
        free(pubKeyExtract);
        return -1;
    }

    *rsa_out = rsa; // output the reconstructed RSA key
    BIO_free(bio);
    free(pubKeyExtract);
    printf("peer public key extracted....\n");
    return 0;
}

// encryption function with the public key of the other person .. not yours ofc
int EncryptedWithPublicKey(unsigned char *message, unsigned char encrypted[256], RSA *rsa){
    int encryptedLen = RSA_public_encrypt(
        strlen((char*)message) + 1, message, encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    if (encryptedLen == -1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return encryptedLen;
}

// decrypt messages sent by the other person with your own key 
int DecryptWithPrivateKey(unsigned char *encryptedMessage, int encryptedLen, unsigned char decrypted[256], RSA *rsa) {
    int decryptedLen = RSA_private_decrypt(
        encryptedLen, encryptedMessage, decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    if (decryptedLen == -1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    // Optionally null-terminate if you expect a string
    decrypted[decryptedLen] = '\0';
    return decryptedLen;
}