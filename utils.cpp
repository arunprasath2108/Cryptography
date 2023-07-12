#include <cstring>
#include <iostream>
#include "utils.hpp"

void printCipherText(unsigned char *cipherText, int cipherText_len) {
    
    for (size_t i = 0; i < cipherText_len; ++i) {
        printf("%02X ", cipherText[i]);
    } 
   
    std::cout << std::endl;
}