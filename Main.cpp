#include <iostream>
#include "aes_cbc.hpp"
#include "aes_ecb.hpp"
#include "aes_gcm.hpp"
#include "ec_algo.hpp"
#include "ec_dsa.hpp"
#include "rsa_algorithm.hpp"

int chooseAlgorithm();
int chooseKeySize(int);
void run_algorithm(int, int);


int main() {

    //choose algorithm to run 
    int userChoice = chooseAlgorithm();

    if(userChoice >= 1 && userChoice <= 6) {

        //choose Key Size
        int keySize = chooseKeySize(userChoice);
        if(keySize != 0 || keySize == 1) {

            //run the specified algorithm with key size.
            run_algorithm(userChoice, keySize);
        } else {
            std::cout << "Invalid key size for the algorithm to execute.\n";
        }
    } else {
        std::cout << "Invalid input for choosing algorithm by choice.\n";
    }
}

int chooseAlgorithm() {

    int input;
    std::cout << "Choose algorithm to run : \n";

    std::cout << "1. AES CBC mode \n";
    std::cout << "2. AES ECB mode \n";
    std::cout << "3. AES GCM mode \n";
    std::cout << "4. RSA \n";
    std::cout << "5. Elliptic Curve \n";
    std::cout << "6. DSA using Elliptic curve \n";

    std::cin >> input;
    return input;
}

int chooseKeySize(int userChoice) {

    std::cout << "choose key size :\n";
    int keySize;

    if(userChoice == 1 || userChoice == 2 || userChoice == 3) {

        std::cout << "KEY SIZE : 16, 24, 32 bytes. \n";
        std::cin >> keySize;
        if(keySize == 16 || keySize == 24 || keySize == 32)
        return keySize;

    } else if(userChoice == 4) {

        std::cout << "KEY SIZE : 1024, 2048, 4096 bits. \n";
        std::cin >> keySize;
        if(keySize == 1024 || keySize == 2048 || keySize == 4096)
        return keySize;
       
    } else if(userChoice == 5 || userChoice == 6) {

        std::cout << "KEY SIZE will be based on Elliptic Curve used in the algorithm. \n\n";
        return 1;

    } else {
        std::cout << " Sorry! Invalid input for key size.\n";
    }
    std::cout << " final 0.";
    return 0;
}

void run_algorithm(int userChoice, int keySize) {


    if(userChoice == 1) {

        std::cout << "Running AES in cbc mode : \n";
        AEScbc* aes_cbc = new AEScbc();
        aes_cbc->run_aes_cbc_algorithm(keySize);
        delete aes_cbc;

    } else if(userChoice == 2) {

        std::cout << "Running AES in ecb mode : \n";
        AESecb* aes_ecb = new AESecb();
        aes_ecb->run_aes_ecb_algorithm(keySize);
        delete aes_ecb;

    } else if(userChoice == 3) {

        std::cout << "Running AES in gcm mode : \n";
        AESgcm* aes_gcm = new AESgcm();
        aes_gcm->run_aes_gcm_algorithm(keySize);
        delete aes_gcm;
 
    } else if(userChoice == 4) {

        std::cout << "Running RSA algorithm : \n";
        RSAalgorithm* rsa = new RSAalgorithm();
        rsa->run_rsa_algorithm(keySize);
        delete rsa;

    } else if(userChoice == 5) {

        std::cout << "Running EC algorithm : \n";
        ECAlgorithm* ec = new ECAlgorithm();
        ec->run_ec_algorithm();
        delete ec;

    } else if(userChoice == 6) {

        std::cout << "Running EC DSA algorithm : \n";
        ECDSAlgorithm* ecdsa = new ECDSAlgorithm();
        ecdsa->run_ec_dsa_algorithm();
        delete ecdsa;

    } 
    else {
        std::cout << " Sorry! Invalid input.\n";
    }
}