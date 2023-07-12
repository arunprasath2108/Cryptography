#include <iostream>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "aes_cbc.hpp"
#include "utils.hpp"
using namespace std;


void AEScbc::run_aes_cbc_algorithm(int keySize) {

    unsigned char key[keySize];
    generate_aes_cbc_key(key, keySize);

    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
        cout << "Error in generating IV." << endl;
        exit(1);
    }

    unsigned char plaintext[] = "This is the message.";
    int plaintext_len = sizeof(plaintext);

    vector<unsigned char> cipherText;
    encrypt_aes_cbc_mode(plaintext, plaintext_len, key, iv, cipherText);

    cout << "Ciphertext: ";
    printCipherText(cipherText.data(), cipherText.size());

    vector<unsigned char> decryptedText;
    decrypt_aes_cbc_mode(cipherText, key, iv, decryptedText);

    cout << "Decrypted Text: " << decryptedText.data() << endl;

}

void AEScbc::generate_aes_cbc_key(unsigned char* key, int KEY_SIZE) {

    if (RAND_bytes(key, KEY_SIZE) != 1) {
        cout << "Error in generating AES key." << endl;
        return;
    }
}

void AEScbc::encrypt_aes_cbc_mode(const unsigned char* plainText, int plaintext_len, const unsigned char* key, const unsigned char* iv, vector<unsigned char>& cipherText) {
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cout << "Error in creating cipher context." << endl;
        return;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        cout << "Error in initializing encryption." << endl;
        return;
    }

    int outLen = 0;
    int cipherTextLen = 0;
    cipherText.resize(plaintext_len + EVP_CIPHER_CTX_block_size(ctx));

    if (EVP_EncryptUpdate(ctx, &cipherText[0], &outLen, plainText, plaintext_len) != 1) {
        cout << "Error in encrypting data." << endl;
        return;
    }
    cipherTextLen += outLen;

    if (EVP_EncryptFinal_ex(ctx, &cipherText[cipherTextLen], &outLen) != 1) {
        cout << "Error in finalizing encryption." << endl;
        return;
    }
    cipherTextLen += outLen;

    cipherText.resize(cipherTextLen);
}

void AEScbc::decrypt_aes_cbc_mode(const vector<unsigned char>& cipherText, const unsigned char* key, const unsigned char* iv, vector<unsigned char>& decryptedText) {
   
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cout << "Error in creating cipher context." << endl;
        return;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        cout << "Error in initializing decryption." << endl;
        return;
    }

    int outLen = 0;
    int decryptedTextLen = 0;
    decryptedText.resize(cipherText.size());

    if (EVP_DecryptUpdate(ctx, &decryptedText[0], &outLen, &cipherText[0], cipherText.size()) != 1) {
        cout << "Error in decrypting data." << endl;
        return;
    }
    decryptedTextLen += outLen;

    if (EVP_DecryptFinal_ex(ctx, &decryptedText[decryptedTextLen], &outLen) != 1) {
        cout << "Error in finalizing decryption." << endl;
        return;
    }
    decryptedTextLen += outLen;

    decryptedText.resize(decryptedTextLen);
}