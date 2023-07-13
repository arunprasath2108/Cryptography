#ifndef AES_CBC_HPP
#define AES_CBC_HPP

class AESCbcAlgorithm {
 
    public:
    void RunAESCbcAlgorithm(int);

    private:
    void GenerateAESCbcKey(unsigned char* , int);
    void EncryptAESCbcMode(const unsigned char* , int , const unsigned char* , const unsigned char* , std::vector<unsigned char>& );
    void DecryptAESCbcMode(const std::vector<unsigned char>& , const unsigned char* , const unsigned char* , std::vector<unsigned char>& );

};

#endif
