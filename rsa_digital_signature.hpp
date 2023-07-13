#ifndef RSA_DSA_HPP
#define RSA_DSA_HPP
#include<openssl/evp.h>

class RSADigitalSignature {

    public:
    void RunRSADigitalSignature(int);
    
    private:
    EVP_PKEY* GenerateRSAKeys(int);
    void DigestMessage(const unsigned char*, size_t input_len, unsigned char*, unsigned int*);
    void SignDigest(EVP_PKEY*, unsigned char*, size_t, unsigned char*, size_t*);
    void VerifySignature(EVP_PKEY*, unsigned char* , size_t , unsigned char* , size_t);

};

#endif