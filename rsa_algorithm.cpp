#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <iostream>
#include "utils.hpp"
#include "rsa_algorithm.hpp"

 
void RSAalgorithm::run_rsa_algorithm(int keySize) {

    unsigned char *cipher_text = NULL, *plain_text = NULL;
    size_t cipherText_len, plainText_len;
    unsigned char input[] = "This is the message.";
    size_t input_len = sizeof(input);

    //key generation
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY* key = NULL;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keySize);
    EVP_PKEY_keygen(ctx, &key); 
 
    std::cout << "Plain text: " << input << "\n";
    //encrypt
    cipher_text = new unsigned char[EVP_PKEY_size(key)];
    encryptRSA(key, &cipher_text, &cipherText_len, input, input_len);

    printCipherText(cipher_text, cipherText_len);
    
    //decrypt
    int size = EVP_PKEY_get_size(key);
    plain_text = new unsigned char[size];

    decryptRSA(key, &plain_text, &plainText_len, cipher_text, cipherText_len);

    std::cout << "\nDecrypted data: " << plain_text << "\n";

    delete[] cipher_text;
    delete[] plain_text;
}

void RSAalgorithm::encryptRSA(EVP_PKEY* key, unsigned char** cipherText, size_t* cipherText_len, unsigned char* plainText, size_t plainText_len) {

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, NULL);
    if(!ctx) {
        std::cerr << "Failed to create context." << std::endl;
        return;
    }

    //initialize
    if(EVP_PKEY_encrypt_init(ctx) <= 0) {
        std::cerr << "Failed to initialize EVP_PKEY_CTX." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    //encrypt plain text
    if(EVP_PKEY_encrypt(ctx, *cipherText, cipherText_len, plainText, plainText_len) <= 0) {
        std::cerr << "Encryption failed." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }
}

void RSAalgorithm::decryptRSA(EVP_PKEY* key, unsigned char** plainText, size_t* plainText_len, unsigned char* cipherText, size_t cipherText_len) {

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, NULL);
    if(!ctx) {
        std::cerr << "Failed to create EVP_PKEY_CTX." << std::endl;
        return;
    }

    //initialize context
    if(EVP_PKEY_decrypt_init(ctx) <= 0) {
        std::cerr << "Failed to initialize EVP_PKEY_CTX." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    // decrypt cipher text
    if(EVP_PKEY_decrypt(ctx, NULL, plainText_len, cipherText, cipherText_len) <= 0) {
        std::cerr << "Failed to determine buffer length." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    if(EVP_PKEY_decrypt(ctx, *plainText, plainText_len, cipherText, cipherText_len) <= 0) {
        std::cerr << "Decryption failed." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }
}