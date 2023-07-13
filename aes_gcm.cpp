#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include "aes_gcm.hpp" 
#include "utils.hpp"
using namespace std;
    

void AESGcmAlgorithm::RunAESGcmAlgorithm(int keysize) {

    const unsigned char plaintext[] = "This is a test plaintext.";
    unsigned char key[keysize];
    GenerateAESGcmKey(key, keysize);   

    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
        cout << "Error in generating IV." << endl;
        exit(1);
    }

    size_t plaintext_size = sizeof(plaintext) - 1;        
    size_t ciphertext_size = plaintext_size;
    unsigned char ciphertext[ciphertext_size];
    unsigned char decrypted[plaintext_size];

    EncryptAESGcmMode(plaintext, plaintext_size, key, iv, sizeof(iv) - 1, ciphertext, decrypted);
    cout << "\nCiphertext: ";
    PrintCipherText(ciphertext, ciphertext_size);

    DecryptAESGcmMode(ciphertext, ciphertext_size, key, iv, sizeof(iv) - 1, decrypted, decrypted);
    cout << "Decrypted: " << decrypted << endl;

}

void AESGcmAlgorithm::EncryptAESGcmMode(const unsigned char* plaintext, size_t plaintext_size, const unsigned char* key, const unsigned char* iv, size_t iv_size, unsigned char* ciphertext, unsigned char* tag) {

    EVP_CIPHER_CTX* ctx;
    int len = 0, ciphertext_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cout << "Error in creating cipher context." << endl;
        return;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1) {
        cout << "Error in initializing encryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, nullptr) != 1) {
        cout << "Error in setting IV length." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
        cout << "Error in initializing encryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_size) != 1) {
        cout << "Error in encrypting data." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        cout << "Error in finalizing encryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        cout << "Error in setting Authentication tag." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    EVP_CIPHER_CTX_free(ctx);
}

void AESGcmAlgorithm::DecryptAESGcmMode(const unsigned char* ciphertext, size_t ciphertext_size, const unsigned char* key, const unsigned char* iv, size_t iv_size, const unsigned char* tag, unsigned char* plaintext) {
    
    EVP_CIPHER_CTX* ctx;
    int len, plaintext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cout << "Error in creating cipher context." << endl;
        return;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1) {
        cout << "Error in initializing decryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, nullptr) != 1) {
        cout << "Error in setting IV length." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
        cout << "Error in initializing decryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_size) != 1) {
        cout << "Error in decrypting data." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
        cout << "Error in setting Tag." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) == 1) {
        cout << "Error in finalizing decryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
}

void AESGcmAlgorithm::GenerateAESGcmKey(unsigned char* key, int keysize) {

    if (RAND_bytes(key, keysize) != 1) {
        cout << "Error in generating AES key." << endl;
        return;
    }
}