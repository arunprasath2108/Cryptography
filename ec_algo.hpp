#ifndef EC_ALGO_HPP
#define EC_ALGO_HPP

#include <openssl/evp.h>

class ECAlgorithm {
 
    public:
    void run_ec_algorithm();

    private:
    EVP_PKEY* generateECCKey();
    void convertToDER(EVP_PKEY*, unsigned char**, int* );
    EVP_PKEY* convertFromDER(const unsigned char*, int );

};


#endif