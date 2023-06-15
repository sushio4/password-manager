#pragma once
#include <stdint.h>
#include <string>

#include "aes.hpp"

class CipherModule
{
private:
    uint8_t* masterKey = nullptr;
    bool validated = false;
    AES* aes256 = nullptr;

public:
    //it'll generate masterKey  from password
    //try to decrypt something
    //and return whether decryption was successfull
    bool validatePassword(const std::string& password); 
    
    //as this is the only class containing masterKey
    //it will be (en/de)crypting everything with those
    //using functions from inside the AES object
    uint8_t* decryptKey(uint8_t* src, long& length);
    uint8_t* encryptKey(uint8_t* src, long& length);

    uint8_t* decryptPassword(AES& aes, uint8_t* src, long& length);
    uint8_t* encryptPassword(AES& aes, uint8_t* src, long& length);

private:
    uint8_t* makeKey(std::string password);
};