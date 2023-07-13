#ifndef RSA_HPP
#define RSA_HPP
#include <openssl/evp.h>

class RSAAlgorithm {

    public:
    void RunRSAAlgorithm(int);
 
    private:
    EVP_PKEY* GenerateRSAKeypair(int);
    void EncryptRSA(EVP_PKEY*, unsigned char**, size_t*, unsigned char*, size_t);
    void DecryptRSA(EVP_PKEY*, unsigned char**, size_t*, unsigned char*, size_t);
        
};

#endif