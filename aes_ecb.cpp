#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream> 
#include <vector>
#include "aes_ecb.hpp"
#include "utils.hpp"
using namespace std;


void AESecb::run_aes_ecb_algorithm(int keySize) {

    const unsigned char plaintext[] = "This is a message to encrypt.";

    //key generation  
    unsigned char key[keySize];
    generate_aes_ecb_key(key, keySize);

    size_t plaintext_size = sizeof(plaintext) - 1;
    size_t cipher_len = plaintext_size + EVP_CIPHER_block_size(EVP_aes_128_ecb());
    size_t decrypt_len = plaintext_size + EVP_MAX_BLOCK_LENGTH;
    unsigned char ciphertext[cipher_len];
    unsigned char decrypted[decrypt_len];

    //encrypt plain text
    aes_ecb_encrypt(plaintext, key, ciphertext, cipher_len);

    //decrypt cipher
    aes_ecb_decrypt(ciphertext, key, decrypted, decrypt_len);

    std::cout << "Plaintext: " << plaintext << std::endl;
    std::cout << "Ciphertext: ";
    printCipherText(ciphertext, plaintext_size);
    std::cout << "Decrypted: " << decrypted << std::endl;
}
 
void AESecb::generate_aes_ecb_key(unsigned char* key, int KEY_SIZE) {

    if (RAND_bytes(key, KEY_SIZE) != 1) {
        std::cout << "Error in generating AES key." << std::endl;
        return;
    }
} 

void AESecb::aes_ecb_encrypt(const unsigned char* plaintext, const unsigned char* key, unsigned char* ciphertext, size_t size) {

    EVP_CIPHER_CTX* ctx;
    int len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cout << "Error in creating cipher context." << endl;
        return;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) != 1) {
        cout << "Error in initializing encryption." << endl;
        return;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, size) != 1) {
        cout << "Error in encrypting data." << endl;
        return;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        cout << "Error in finalizing encryption." << endl;
        return;
    }
}

void AESecb::aes_ecb_decrypt(const unsigned char* ciphertext, const unsigned char* key, unsigned char* plaintext, size_t size) {

    EVP_CIPHER_CTX* ctx;
    int len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cout << "Error in creating cipher context." << endl;
        return;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) != 1) {
        cout << "Error in initializing decryption." << endl;
        return;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, size) != 1) {
        cout << "Error in decrypting data." << endl;
        return;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) == 1) {
        cout << "Error in finalizing decryption." << endl;
        return;
    }

}



