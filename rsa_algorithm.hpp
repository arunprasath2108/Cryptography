#ifndef RSA_HPP
#define RSA_HPP

#include <openssl/evp.h>

class RSAalgorithm {

    public:
    void run_rsa_algorithm(int);

    private:
    void encryptRSA(EVP_PKEY*, unsigned char**, size_t*, unsigned char*, size_t);
    void decryptRSA(EVP_PKEY*, unsigned char**, size_t*, unsigned char*, size_t);
        
};

#endif