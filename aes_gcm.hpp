#ifndef AES_GCM_HPP
#define AES_GCM_HPP


class AESGcmAlgorithm {
    
    public:
    void RunAESGcmAlgorithm(int);

    private:
    void GenerateAESGcmKey(unsigned char*, int);
    void EncryptAESGcmMode(const unsigned char*, size_t, const unsigned char*, const unsigned char*, size_t, unsigned char*, unsigned char*);
    void DecryptAESGcmMode(const unsigned char*, size_t, const unsigned char*, const unsigned char*, size_t, const unsigned char*, unsigned char*);
};

#endif