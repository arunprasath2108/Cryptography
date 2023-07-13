#ifndef AES_ECB_HPP
#define AES_ECB_HPP


class AESEcbAlgorithm {

    public:
    void RunAESEcbAlgorithm(int);

    private:
    void GenerateAESEcbKey(unsigned char*, int);
    void EncryptAESEcbMode(const unsigned char*, const unsigned char*, unsigned char*, size_t);
    void DecryptAESEcbMode(const unsigned char*, const unsigned char*, unsigned char*, size_t);

};

#endif