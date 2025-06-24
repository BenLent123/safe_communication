#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <stddef.h>

// Key generation and cleanup
void CleanUp(RSA *rsa, BIGNUM *bn, BIO *pub, char *pub_key);
int GenerateKey(RSA **rsa, BIGNUM **bn, char **pubKey, size_t *pubKeyLen);

// Public key export/import
int SendPublicKey(int socketfd, size_t pubKeyLen, char *pubKey);
int ExtractPublicKey(int socketfd, RSA **rsa_out);

// Encryption/Decryption
int EncryptedWithPublicKey(unsigned char *message, unsigned char encrypted[256], RSA *rsa);
int DecryptWithPrivateKey(unsigned char *encryptedMessage, int encryptedLen, unsigned char decrypted[256], RSA *rsa);

#endif // TRY_H