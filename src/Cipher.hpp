#pragma once
#include <stdint.h>
#include <string>

#include "aes.hpp"

class CipherModule
{
private:
    uint8_t* masterKey = nullptr;
    bool validated = false;

public:
    //it'll generate masterKey  from password
    //try to decrypt something
    //and return whether decryption was successfull
    bool validatePassword(const std::string& password); 
    
    //as this is the only class containing masterKey
    //it will be (en/de)crypting everything with those
    //using functions from inside the AES object
    bool decryptKey(AES& aes, const uint8_t* src, uint8_t* dest, uint8_t length);
    bool encryptKey(AES& aes, const uint8_t* src, uint8_t* dest, uint8_t length);

    bool decryptPassword(AES& aes, const uint8_t* src, uint8_t* dest, uint8_t length);
    bool encryptPassword(AES& aes, const uint8_t* src, uint8_t* dest, uint8_t length);
};