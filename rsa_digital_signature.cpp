#include <iostream>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "rsa_digital_signature.hpp"
#include "utils.hpp"
using namespace std;

void RSADigitalSignature::RunRSADigitalSignature(int keysize) {

    unsigned char input[] = "This is the message.";
    size_t input_len = sizeof(input);
    unsigned char message_digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    //key generation
    EVP_PKEY* rsa_keypair = GenerateRSAKeys(keysize);

    //get the hash digest.
    DigestMessage(input, input_len, message_digest, &digest_len);
    cout << "\nPrinting hash digest :\n";
    PrintCipherText(message_digest, digest_len);

    size_t signature_len = EVP_PKEY_size(rsa_keypair);
    unsigned char* signature = new unsigned char[signature_len];

    // Sign the digest
    SignDigest(rsa_keypair, message_digest, digest_len, signature, &signature_len);

    // Verify the signature
    VerifySignature(rsa_keypair, message_digest, digest_len, signature, signature_len);

    EVP_PKEY_free(rsa_keypair);
    delete[] signature;
}

EVP_PKEY* RSADigitalSignature::GenerateRSAKeys(int keysize) {

    int keysize_in_bits = keysize * 8;
    EVP_PKEY* rsa_keypair = NULL;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (ctx == NULL)
    {
        cout << "error in ctx.\n";
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        cout << "error in init of keygen.\n";
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keysize_in_bits) <= 0)
    {
        cout << "error in setting key param.\n";
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(ctx, &rsa_keypair) <= 0)
    {
        cout << "error in generating key.\n";
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return rsa_keypair;
}

void RSADigitalSignature::DigestMessage(const unsigned char *input_message, size_t input_len, unsigned char *message_digest, unsigned int *digest_len) {
	
    EVP_MD_CTX *message_digest_ctx = EVP_MD_CTX_new();
    if(message_digest_ctx == NULL) {
        cout << "Can't create a new ctx.\n";
        return;
    }

    if(EVP_DigestInit(message_digest_ctx, EVP_sha256()) != 1) {
        cout << "can't initialize a message digest.\n";
        EVP_MD_CTX_free(message_digest_ctx);
        return;
    }

    if(EVP_DigestUpdate(message_digest_ctx, input_message, input_len) != 1) {
        cout << "Can't update the hash value in ctx.\n";
        EVP_MD_CTX_free(message_digest_ctx);
        return;
    }

    if(EVP_DigestFinal(message_digest_ctx, message_digest, digest_len) != 1) {
        cout << "Can't get the digest value into message_digest.\n";
        EVP_MD_CTX_free(message_digest_ctx);
        return;
    }
    EVP_MD_CTX_free(message_digest_ctx);
}

void RSADigitalSignature::SignDigest(EVP_PKEY* rsa_keypair, unsigned char* message_digest, size_t digest_len, unsigned char* signature, size_t* signature_len) {
   
    EVP_MD_CTX* signing_ctx = EVP_MD_CTX_new();
    if (!signing_ctx) {
        cout << "Error creating signing context.\n";
        return;
    }

    if (EVP_DigestSignInit(signing_ctx, NULL, EVP_sha256(), NULL, rsa_keypair) != 1) {
        cout << "Error in sign init.\n";
        EVP_MD_CTX_free(signing_ctx);
        return;
    }

    if (EVP_DigestSign(signing_ctx, signature, signature_len, message_digest, digest_len) != 1) {
        cout << "Error in signing.\n";
        EVP_MD_CTX_free(signing_ctx);
        return;
    }

    cout << "Digest signed successful.\n";
    EVP_MD_CTX_free(signing_ctx);
}

void RSADigitalSignature::VerifySignature(EVP_PKEY* rsa_keypair, unsigned char* message_digest, size_t digest_len, unsigned char* signature, size_t signature_len) {

    EVP_MD_CTX* verify_ctx = EVP_MD_CTX_new();
    if (!verify_ctx) {
        cout << "Error creating verify context.\n";
        return;
    }

    if (EVP_DigestVerifyInit(verify_ctx, NULL, EVP_sha256(), NULL, rsa_keypair) != 1) {
        cout << "Error in verify init.\n";
        EVP_MD_CTX_free(verify_ctx);
        return;
    }

    if (EVP_DigestVerify(verify_ctx, signature, signature_len, message_digest, digest_len) != 1) {
        cout << "Signature verification failed.\n";
        EVP_MD_CTX_free(verify_ctx);
        return;
    }

    cout << "Sign verification success.\n";
    EVP_MD_CTX_free(verify_ctx);
}

