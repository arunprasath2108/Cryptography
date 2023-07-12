#ifndef AES_GCM_HPP
#define AES_GCM_HPP
#include <cstring>

class AESgcm {

    public:
    void run_aes_gcm_algorithm(int);

    private:
    void generate_aes_gcm_key(unsigned char*, int);
    void aes_gcm_encrypt(const unsigned char*, size_t, const unsigned char*, const unsigned char*, size_t, unsigned char*, unsigned char*, size_t);
    void aes_gcm_decrypt(const unsigned char*, size_t, const unsigned char*, const unsigned char*, size_t, const unsigned char*, unsigned char*, size_t);
    
};

#endif