#ifndef EC_ALGO_HPP
#define EC_ALGO_HPP
#include <openssl/evp.h>

class ECAlgorithm {
 
    public:
    void RunECAlgorithm();

    private:
    EVP_PKEY* GenerateECKey();
    void ConvertToDER(EVP_PKEY*, unsigned char**, int* );
    EVP_PKEY* ConvertFromDER(const unsigned char*, int );

};


#endif