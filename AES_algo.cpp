#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <string>
#include <vector>
using namespace std;

void generateAESKey(unsigned char*, int);
void encryptAES(const unsigned char*, int, const unsigned char*, const unsigned char*, vector<unsigned char>&);
void decryptAES(const vector<unsigned char>&, const unsigned char*, const unsigned char*, vector<unsigned char>&);
void printCipherText(unsigned char*, int);

int main() {

    const int KEY_SIZE = 24; 
    unsigned char key[KEY_SIZE];
    generateAESKey(key, KEY_SIZE);

    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (RAND_bytes(iv, EVP_MAX_IV_LENGTH) != 1) {
        cout << "Error in generating IV." << endl;
        exit(1);
    }

    unsigned char plaintext[] = "This is the message.";
    int plaintext_len = sizeof(plaintext);

    vector<unsigned char> cipherText;
    encryptAES(plaintext, plaintext_len, key, iv, cipherText);

    cout << "Ciphertext: ";
    printCipherText(cipherText.data(), cipherText.size());

    vector<unsigned char> decryptedText;
    decryptAES(cipherText, key, iv, decryptedText);

    cout << "Decrypted Text: " << decryptedText.data() << endl;

    return 0;
}

void generateAESKey(unsigned char* key, int KEY_SIZE) {

    if (RAND_bytes(key, KEY_SIZE) != 1) {
        cout << "Error in generating AES key." << endl;
        return;
    }
}

void encryptAES(const unsigned char* plainText, int plaintext_len, const unsigned char* key, const unsigned char* iv, vector<unsigned char>& cipherText) {
    
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

void decryptAES(const vector<unsigned char>& cipherText, const unsigned char* key, const unsigned char* iv, vector<unsigned char>& decryptedText) {
   
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

void printCipherText(unsigned char *cipherText, int cipherText_len) {
    
    for (size_t i = 0; i < cipherText_len; ++i) {
        printf("%02X ", cipherText[i]);
    }

    std::cout << std::endl;
}