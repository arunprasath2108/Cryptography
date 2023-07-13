#include <cstring>
#include <iostream>
#include "utils.hpp"

void PrintCipherText(unsigned char *ciphertext, int ciphertext_len) {
    
    for (size_t i = 0; i < ciphertext_len; ++i) {
        printf("%02X ", ciphertext[i]);
    } 
   
    std::cout << std::endl;
}
