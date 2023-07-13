#include <iostream>
#include "aes_cbc.hpp"
#include "aes_ecb.hpp"
#include "aes_gcm.hpp"
#include "ec_algorithm.hpp"
#include "ec_digital_signature.hpp"
#include "rsa_algorithm.hpp"
#include "rsa_digital_signature.hpp"

int ChooseAlgorithm();
int ChooseKeySize(int);
void RunAlgorithm(int, int);


int main() {

    //choose algorithm to run 
    int user_choice = ChooseAlgorithm();

    if(user_choice >= 1 && user_choice <= 7) {

        //choose Key Size
        int keysize = ChooseKeySize(user_choice);
        if(keysize != 0 || keysize == 1) {

            //run the specified algorithm with key size.
            RunAlgorithm(user_choice, keysize);
        } else {
            std::cout << "Invalid key size for the algorithm to execute.\n";
        }
    } else {
        std::cout << "Invalid input for choosing algorithm by choice.\n";
    }
}

int ChooseAlgorithm() {

    int input;
    std::cout << "Choose algorithm to run : \n";

    std::cout << "1. AES CBC mode \n";
    std::cout << "2. AES ECB mode \n";
    std::cout << "3. AES GCM mode \n";
    std::cout << "4. RSA \n";
    std::cout << "5. Elliptic Curve \n";
    std::cout << "6. DSA using Elliptic curve \n";
    std::cout << "7. DSA using RSA algorithm.\n";

    std::cin >> input;
    return input;
}

int ChooseKeySize(int user_choice) {

    std::cout << "choose key size :\n";
    int keysize;

    if(user_choice == 1 || user_choice == 2 || user_choice == 3) {

        std::cout << "KEY SIZE : 16, 24, 32 bytes. \n";
        std::cin >> keysize;
        if(keysize == 16 || keysize == 24 || keysize == 32)
        return keysize;

    } else if(user_choice == 4 || user_choice == 7) {

        std::cout << "KEY SIZE : 128, 256, 512 bytes. \n";
        std::cin >> keysize;
        if(keysize == 128 || keysize == 256 || keysize == 512)
        return keysize;
       
    } else if(user_choice == 5 || user_choice == 6) {

        std::cout << "KEY SIZE will be based on Elliptic Curve used in the algorithm. \n\n";
        return 1;

    } else {
        std::cout << " Sorry! Invalid input for key size.\n";
    }

    return 0;
}

void RunAlgorithm(int user_choice, int keysize) {

    std::cout << std::endl;
    if(user_choice == 1) {

        std::cout << "Running AES in cbc mode : \n";
        AESCbcAlgorithm* aes_cbc = new AESCbcAlgorithm();
        aes_cbc->RunAESCbcAlgorithm(keysize);
        delete aes_cbc;

    } else if(user_choice == 2) {

        std::cout << "Running AES in ecb mode : \n";
        AESEcbAlgorithm* aes_ecb = new AESEcbAlgorithm();
        aes_ecb->RunAESEcbAlgorithm(keysize);
        delete aes_ecb;

    } else if(user_choice == 3) {

        std::cout << "Running AES in gcm mode : \n";
        AESGcmAlgorithm* aes_gcm = new AESGcmAlgorithm();
        aes_gcm->RunAESGcmAlgorithm(keysize);
        delete aes_gcm;
 
    } else if(user_choice == 4) {

        std::cout << "Running RSA algorithm : \n";
        RSAAlgorithm* rsa = new RSAAlgorithm();
        rsa->RunRSAAlgorithm(keysize);
        delete rsa;

    } else if(user_choice == 5) {

        std::cout << "Running EC algorithm : \n";
        ECAlgorithm* ec = new ECAlgorithm();
        ec->RunECAlgorithm();
        delete ec;

    } else if(user_choice == 6) {

        std::cout << "Running EC DSA algorithm : \n";
        ECDigitalSignature* ecdsa = new ECDigitalSignature();
        ecdsa->RunECDSA();
        delete ecdsa;

    } else if (user_choice == 7) {

        std::cout << "Running DSA using RSA algorithm : \n";
        RSADigitalSignature* rsa_dsa = new RSADigitalSignature();
        rsa_dsa->RunRSADigitalSignature(keysize);
        delete rsa_dsa;

    } else {
        std::cout << " Sorry! Invalid input.\n";
    }
}