#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream> 
#include <vector>
#include "aes_ecb.hpp"
#include "utils.hpp"
using namespace std;


void AESEcbAlgorithm::RunAESEcbAlgorithm(int keysize) {

    const unsigned char plaintext[] = "This is a message to encrypt.";

    //key generation  
    unsigned char key[keysize];
    GenerateAESEcbKey(key, keysize);

    size_t plaintext_size = sizeof(plaintext) - 1;
    size_t cipher_len = plaintext_size + EVP_CIPHER_block_size(EVP_aes_128_ecb());
    size_t decrypt_len = plaintext_size + EVP_MAX_BLOCK_LENGTH;
    unsigned char ciphertext[cipher_len];
    unsigned char decrypted[decrypt_len];

    //encrypt plain text
    EncryptAESEcbMode(plaintext, key, ciphertext, cipher_len);

    //decrypt cipher
    DecryptAESEcbMode(ciphertext, key, decrypted, decrypt_len);

    std::cout << "\nPlaintext: " << plaintext << std::endl;
    std::cout << "Ciphertext: ";
    PrintCipherText(ciphertext, plaintext_size);
    std::cout << "Decrypted: " << decrypted << std::endl;
}
 
void AESEcbAlgorithm::GenerateAESEcbKey(unsigned char* key, int keysize) {

    if (RAND_bytes(key, keysize) != 1) {
        std::cout << "Error in generating AES key." << std::endl;
        return;
    }
} 

void AESEcbAlgorithm::EncryptAESEcbMode(const unsigned char* plaintext, const unsigned char* key, unsigned char* ciphertext, size_t size) {

    EVP_CIPHER_CTX* ctx;
    int len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cout << "Error in creating cipher context." << endl;
        return;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) != 1) {
        cout << "Error in initializing encryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, size) != 1) {
        cout << "Error in encrypting data." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        cout << "Error in finalizing encryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    EVP_CIPHER_CTX_free(ctx);
}

void AESEcbAlgorithm::DecryptAESEcbMode(const unsigned char* ciphertext, const unsigned char* key, unsigned char* plaintext, size_t size) {

    EVP_CIPHER_CTX* ctx;
    int len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cout << "Error in creating cipher context." << endl;
        return;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) != 1) {
        cout << "Error in initializing decryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, size) != 1) {
        cout << "Error in decrypting data." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) == 1) {
        cout << "Error in finalizing decryption." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    EVP_CIPHER_CTX_free(ctx);

}