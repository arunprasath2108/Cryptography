#include<iostream>
// #include <openssl/evp.h>
#include <openssl/ec.h>
#include "utils.hpp"
#include "ec_dsa.hpp"
using namespace std; 

void ECDSAlgorithm::run_ec_dsa_algorithm() {

    unsigned char input[] = "EC algorithm to sign a message and verify it.";
    size_t input_len = sizeof(input);
    unsigned char message_digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    
    //get the hash digest.
    digest_message(input, input_len, message_digest, &digest_len);
    cout << "printing hash digest :\n";
    printCipherText(message_digest, digest_len);

    //generate keys.
    EVP_PKEY* ec_keypair = generate_ec_keys();
    
    size_t signature_len = EVP_PKEY_size(ec_keypair);
    unsigned char* signature = new unsigned char[signature_len];

    // Sign the digest
    signDigest(ec_keypair, message_digest, digest_len, signature, &signature_len);

    // Verify the signature
    verifySignature(ec_keypair, message_digest, digest_len, signature, signature_len);
    
}

EVP_PKEY* ECDSAlgorithm::generate_ec_keys()
{

    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

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

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp192k1) <= 0)
    {
        cout << "error in setting EC params.\n";
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        cout << "error in generating key.\n";
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

void ECDSAlgorithm::digest_message(const unsigned char *input_message, size_t input_len, unsigned char *message_digest, unsigned int *digest_len) {
	
    EVP_MD_CTX *message_digest_ctx = EVP_MD_CTX_new();
    if(message_digest_ctx == NULL) {
        cout << "Can't create a new ctx.\n";
        return;
    }

    if(EVP_DigestInit(message_digest_ctx, EVP_sha256()) != 1) {
        cout << "can't initialize a message digest.\n";
        return;
    }

    if(EVP_DigestUpdate(message_digest_ctx, input_message, input_len) != 1) {
        cout << "Can't update the hash value in ctx.\n";
        return;
    }

    if(EVP_DigestFinal(message_digest_ctx, message_digest, digest_len) != 1) {
        cout << "Can't get the digest value into message_digest.\n";
        return;
    }
}

void ECDSAlgorithm::signDigest(EVP_PKEY* ec_keypair, unsigned char* message_digest, size_t digest_len, unsigned char* signature, size_t* signature_len) {
   
    EVP_MD_CTX* signingCtx = EVP_MD_CTX_new();
    if (!signingCtx) {
        cout << "Error creating signing context.\n";
        return;
    }

    if (EVP_DigestSignInit(signingCtx, NULL, EVP_sha256(), NULL, ec_keypair) != 1) {
        cout << "Error in sign init.\n";
        return;
    }

    if (EVP_DigestSign(signingCtx, signature, signature_len, message_digest, digest_len) != 1) {
        cout << "Error in signing.\n";
        return;
    }

    cout << "Digest signed successful.\n";
}

void ECDSAlgorithm::verifySignature(EVP_PKEY* ec_keypair, unsigned char* message_digest, size_t digest_len, unsigned char* signature, size_t signature_len) {

    EVP_MD_CTX* verifyCtx = EVP_MD_CTX_new();
    if (!verifyCtx) {
        cout << "Error creating verify context.\n";
        return;
    }

    if (EVP_DigestVerifyInit(verifyCtx, NULL, EVP_sha256(), NULL, ec_keypair) != 1) {
        cout << "Error in verify init.\n";
        return;
    }

    if (EVP_DigestVerify(verifyCtx, signature, signature_len, message_digest, digest_len) != 1) {
        cout << "Signature verification failed.\n";
        return;
    }

    cout << "Sign verification success.\n";
}


