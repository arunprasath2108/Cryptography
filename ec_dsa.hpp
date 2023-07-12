#ifndef EC_DSA_HPP
#define EC_DSA_HPP

#include <openssl/evp.h>

class ECDSAlgorithm {

    public:
    void run_ec_dsa_algorithm();

    private:
    EVP_PKEY* generate_ec_keys();
    void digest_message(const unsigned char*, size_t, unsigned char*, unsigned int*);
    void signDigest(EVP_PKEY*, unsigned char*, size_t, unsigned char*, size_t*);
    void verifySignature(EVP_PKEY* , unsigned char*, size_t, unsigned char*, size_t);

};

#endif
