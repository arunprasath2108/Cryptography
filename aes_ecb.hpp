#ifndef AES_ECB_HPP
#define AES_ECB_HPP

#include <cstring>

class AESecb {

    public:
    void run_aes_ecb_algorithm(int);

    private:
    void generate_aes_ecb_key(unsigned char*, int);
    void aes_ecb_encrypt(const unsigned char*, const unsigned char*, unsigned char*, size_t);
    void aes_ecb_decrypt(const unsigned char*, const unsigned char*, unsigned char*, size_t);

};

#endif