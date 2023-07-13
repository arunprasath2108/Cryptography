#ifndef EC_DSA_HPP
#define EC_DSA_HPP
#include <openssl/evp.h>

class ECDigitalSignature {

    public:
    void RunECDSA();

    private:
    EVP_PKEY* GenerateECKeys();
    void DigestMessage(const unsigned char*, size_t, unsigned char*, unsigned int*);
    void SignDigest(EVP_PKEY*, unsigned char*, size_t, unsigned char*, size_t*);
    void VerifySignature(EVP_PKEY* , unsigned char*, size_t, unsigned char*, size_t);

};

#endif
