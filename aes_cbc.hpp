#ifndef AES_CBC_HPP
#define AES_CBC_HPP

class AEScbc {

    public:
    void run_aes_cbc_algorithm(int);

    private:
    void generate_aes_cbc_key(unsigned char* , int);
    void encrypt_aes_cbc_mode(const unsigned char* , int , const unsigned char* , const unsigned char* , std::vector<unsigned char>& );
    void decrypt_aes_cbc_mode(const std::vector<unsigned char>& , const unsigned char* , const unsigned char* , std::vector<unsigned char>& );

};

#endif
