#include <iostream>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
using namespace std;

void digest_message(const unsigned char*, size_t , unsigned char*, unsigned int*);
EVP_PKEY* generateDSAkey();
void signDigest(EVP_PKEY*, unsigned char*, size_t, unsigned char*, size_t*);
void verifySignature(EVP_PKEY*, unsigned char*, size_t, unsigned char*, size_t);
void printCipherText(unsigned char*, int);

int main() {

    unsigned char input[] = "DSA algorithm to sign a message and verify it.";
    size_t input_len = sizeof(input);
    unsigned char message_digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    
    //get the hash digest.
    digest_message(input, input_len, message_digest, &digest_len);
    cout << "printing hash digest :\n";
    printCipherText(message_digest, digest_len);

    //generate keys.
    EVP_PKEY* dsaKeyPair = generateDSAkey();
    
    size_t signature_len = EVP_PKEY_size(dsaKeyPair);
    unsigned char* signature = new unsigned char[signature_len];

    // Sign the digest
    signDigest(dsaKeyPair, message_digest, digest_len, signature, &signature_len);

    // Verify the signature
    verifySignature(dsaKeyPair, message_digest, digest_len, signature, signature_len);

    return 0;
}

void digest_message(const unsigned char *input_message, size_t input_len, unsigned char *message_digest, unsigned int *digest_len) {
	
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

EVP_PKEY* generateDSAkey() {

    unsigned int pbits = 2048;
    unsigned int qbits = 256;
    int gindex = 1;
    OSSL_PARAM params[5];
    EVP_PKEY *param_key = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    // Create a context for DSA parameter generation
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL);
    if (!pctx) {
        std::cout << "Error creating ctx for DSA parameter generation.\n";
        return NULL;
    }

    // Initialize DSA parameter generation
    if (EVP_PKEY_paramgen_init(pctx) <= 0) {
        std::cout << "Error in init DSA parameter.\n";
        return NULL;
    }

    // Set the DSA parameter generation parameters
    params[0] = OSSL_PARAM_construct_uint("pbits", &pbits);
    params[1] = OSSL_PARAM_construct_uint("qbits", &qbits);
    params[2] = OSSL_PARAM_construct_int("gindex", &gindex);
    params[3] = OSSL_PARAM_construct_utf8_string("digest", (char*)"SHA384", 0);
    params[4] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(pctx, params) <= 0) {
        std::cout << "Error setting DSA generation params.\n";
        return NULL;
    }

    // Generate DSA parameters
    if (EVP_PKEY_generate(pctx, &param_key) <= 0) {
        std::cout << "Error generating DSA param.\n";
        return NULL;
    }

    // Print DSA parameters
    // BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    // EVP_PKEY_print_params(bio_out, param_key, 0, NULL);
    // std::cout << "DSA parameters generated successfully.\n";

    // Create a context for DSA key generation
    EVP_PKEY_CTX *key_ctx = NULL;
    key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, param_key, NULL);
    if (!key_ctx) {
        std::cout << "Error creating EVP_PKEY_CTX for DSA key gen.\n";
        return NULL;
    }

    // Initialize DSA key generation
    if (EVP_PKEY_keygen_init(key_ctx) <= 0) {
        std::cout << "Error init DSA key generation.\n";
        return NULL;
    }

    // Generate DSA key pair
    EVP_PKEY *key = NULL;
    if (EVP_PKEY_generate(key_ctx, &key) <= 0) {
        std::cout << "Error generating DSA key pair.\n";
        return NULL;
    }

    // Print DSA private key
    // EVP_PKEY_print_private(bio_out, key, 0, NULL);
    std::cout << "DSA key-pair generated.\n";
    return key;
}

void signDigest(EVP_PKEY* dsaKeyPair, unsigned char* message_digest, size_t digest_len, unsigned char* signature, size_t* signature_len) {
   
    EVP_MD_CTX* signingCtx = EVP_MD_CTX_new();
    if (!signingCtx) {
        cout << "Error creating signing context.\n";
        return;
    }

    if (EVP_DigestSignInit(signingCtx, NULL, EVP_sha256(), NULL, dsaKeyPair) != 1) {
        cout << "Error in sign init.\n";
        return;
    }

    if (EVP_DigestSign(signingCtx, signature, signature_len, message_digest, digest_len) != 1) {
        cout << "Error in signing.\n";
        return;
    }

    cout << "Digest signed successful.\n";
}

void verifySignature(EVP_PKEY* dsaKeyPair, unsigned char* message_digest, size_t digest_len, unsigned char* signature, size_t signature_len) {

    EVP_MD_CTX* verifyCtx = EVP_MD_CTX_new();
    if (!verifyCtx) {
        cout << "Error creating verify context.\n";
        return;
    }

    if (EVP_DigestVerifyInit(verifyCtx, NULL, EVP_sha256(), NULL, dsaKeyPair) != 1) {
        cout << "Error in verify init.\n";
        return;
    }

    if (EVP_DigestVerify(verifyCtx, signature, signature_len, message_digest, digest_len) != 1) {
        cout << "Signature verification failed.\n";
        return;
    }

    cout << "Signature verification successful.\n";
}

void printCipherText(unsigned char *cipherText, int cipherText_len) {
    
    for (size_t i = 0; i < cipherText_len; ++i) {
        printf("%02X ", cipherText[i]);
    }

    std::cout << std::endl;
}

