#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <iostream>
#include "utils.hpp"
#include "rsa_algorithm.hpp"

 
void RSAAlgorithm::RunRSAAlgorithm(int keysize) {

    unsigned char *ciphertext = NULL, *plaintext = NULL;
    size_t ciphertext_len, plaintext_len;
    unsigned char input[] = "This is the message.";
    size_t input_len = sizeof(input);

    //key generation
    EVP_PKEY* rsa_keypair = GenerateRSAKeypair(keysize);
 
    std::cout << "\nPlain text: " << input << "\n";
    //encrypt
    ciphertext = new unsigned char[EVP_PKEY_size(rsa_keypair)];
    EncryptRSA(rsa_keypair, &ciphertext, &ciphertext_len, input, input_len);
    std::cout << "Cipher text : ";
    PrintCipherText(ciphertext, ciphertext_len);
    
    //decrypt
    int size = EVP_PKEY_get_size(rsa_keypair);
    plaintext = new unsigned char[size];

    DecryptRSA(rsa_keypair, &plaintext, &plaintext_len, ciphertext, ciphertext_len);

    std::cout << "Decrypted data: " << plaintext << "\n";
 
    delete[] ciphertext;
    delete[] plaintext;
    EVP_PKEY_free(rsa_keypair);
}

EVP_PKEY* RSAAlgorithm::GenerateRSAKeypair(int keysize) {

    int keysize_in_bits = keysize * 8;
    EVP_PKEY* rsa_keypair = NULL;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (ctx == NULL)
    {
        std::cout << "error in ctx.\n";
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        std::cout << "error in init of keygen.\n";
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keysize_in_bits) <= 0)
    {
        std::cout << "error in setting key param.\n";
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(ctx, &rsa_keypair) <= 0)
    {
        std::cout << "error in generating key.\n";
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return rsa_keypair;
}

void RSAAlgorithm::EncryptRSA(EVP_PKEY* key, unsigned char** ciphertext, size_t* ciphertext_len, unsigned char* plaintext, size_t plaintext_len) {

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
    if(EVP_PKEY_encrypt(ctx, *ciphertext, ciphertext_len, plaintext, plaintext_len) <= 0) {
        std::cerr << "Encryption failed." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    EVP_PKEY_CTX_free(ctx);
}

void RSAAlgorithm::DecryptRSA(EVP_PKEY* key, unsigned char** plaintext, size_t* plaintext_len, unsigned char* ciphertext, size_t ciphertext_len) {

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
    if(EVP_PKEY_decrypt(ctx, NULL, plaintext_len, ciphertext, ciphertext_len) <= 0) {
        std::cerr << "Failed to determine buffer length." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    if(EVP_PKEY_decrypt(ctx, *plaintext, plaintext_len, ciphertext, ciphertext_len) <= 0) {
        std::cerr << "Decryption failed." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    EVP_PKEY_CTX_free(ctx);
}