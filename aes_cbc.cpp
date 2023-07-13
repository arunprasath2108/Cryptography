#include <iostream>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "aes_cbc.hpp"
#include "utils.hpp"
using namespace std;


void AESCbcAlgorithm::RunAESCbcAlgorithm(int keysize) {
  
    unsigned char key[keysize];
    GenerateAESCbcKey(key, keysize);

    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
        cout << "Error in generating IV." << endl;
        exit(1);
    }

    unsigned char plaintext[] = "This is the message.";
    int plaintext_len = sizeof(plaintext);

    vector<unsigned char> ciphertext;
    EncryptAESCbcMode(plaintext, plaintext_len, key, iv, ciphertext);
    cout << "\nPlaintext : " << plaintext << endl;
    cout << "Ciphertext: ";
    PrintCipherText(ciphertext.data(), ciphertext.size());

    vector<unsigned char> decrypted_text;
    DecryptAESCbcMode(ciphertext, key, iv, decrypted_text);

    cout << "Decrypted Text: " << decrypted_text.data() << endl;
}

void AESCbcAlgorithm::GenerateAESCbcKey(unsigned char* key, int keysize) {

    if (RAND_bytes(key, keysize) != 1) {
        cout << "Error in generating AES key." << endl;
        return;
    }
}

void AESCbcAlgorithm::EncryptAESCbcMode(const unsigned char* plaintext, int plaintext_len, const unsigned char* key, const unsigned char* iv, vector<unsigned char>& ciphertext) {
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cout << "Error in creating cipher context." << endl;
        return;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        cout << "Error in initializing encryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int out_len = 0;
    int ciphertext_len = 0;
    ciphertext.resize(plaintext_len + EVP_CIPHER_CTX_block_size(ctx));

    if (EVP_EncryptUpdate(ctx, &ciphertext[0], &out_len, plaintext, plaintext_len) != 1) {
        cout << "Error in encrypting data." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len += out_len;

    if (EVP_EncryptFinal_ex(ctx, &ciphertext[ciphertext_len], &out_len) != 1) {
        cout << "Error in finalizing encryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len += out_len;

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
}

void AESCbcAlgorithm::DecryptAESCbcMode(const vector<unsigned char>& ciphertext, const unsigned char* key, const unsigned char* iv, vector<unsigned char>& decrypted_text) {
   
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cout << "Error in creating cipher context." << endl;
        return;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        cout << "Error in initializing decryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int out_len = 0;
    int decryptedtext_len = 0;
    decrypted_text.resize(ciphertext.size());

    if (EVP_DecryptUpdate(ctx, &decrypted_text[0], &out_len, &ciphertext[0], ciphertext.size()) != 1) {
        cout << "Error in decrypting data." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    decryptedtext_len += out_len;

    if (EVP_DecryptFinal_ex(ctx, &decrypted_text[decryptedtext_len], &out_len) != 1) {
        cout << "Error in finalizing decryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    decryptedtext_len += out_len;

    decrypted_text.resize(decryptedtext_len);
    EVP_CIPHER_CTX_free(ctx);
}