#include "Cipher.hpp"
#include <cstring>
#include <fstream>

uint8_t* CipherModule::makeKey(std::string password)
{
    //maybe it's not the safest, but it kinda works
    while(password.size() < 256/8) password += password; //artificially leghten it to fit the key length
    password = password.substr(0, 256/8); //truncate it to be exactly 256 bits
    uint8_t* key = new uint8_t[256/8];
    memcpy(key, password.c_str(), 256/8);
    return key;
}

bool CipherModule::validatePassword(const std::string& password)
{
    masterKey = makeKey(password);

    std::ifstream valFile("val.bin");
    if(!valFile)
    {
        //first time login
        std::ofstream valFile("val.bin", std::ios::out | std::ios::binary);
        aes256 = new AES256(0, masterKey, nullptr, nullptr);

        long length = 11;
        char* val = new char[12];
        memcpy(val, "magic_value", 12);
        auto encrypted = aes256->encrypt((uint8_t*)val, length);

        valFile.write((char*)&length, sizeof(long));
        valFile.write((char*)encrypted, length);
        valFile.close();
        return validated = true;
    }
    
    long length;
    valFile.read((char*)&length, sizeof(long));

    auto encrypted = new uint8_t[length];
    valFile.read((char*)encrypted, length);

    delete aes256;
    aes256 = new AES256(0, masterKey, nullptr, nullptr);

    auto res = (char*)aes256->decrypt(encrypted, length);
    std::string decrypted = res ? res : "";

    return validated = (decrypted == "magic_value");
}

//added by 272234

uint8_t *CipherModule::decryptPassword(AES &aes, uint8_t *src, long& length) 
{
    auto ptr = aes.decrypt(src, length);
    auto copy = new uint8_t[length+1];
    memcpy(copy, ptr, length);
    copy[length] = '\0';
    return copy;
}

uint8_t *CipherModule::encryptPassword(AES &aes, uint8_t *src, long& length) 
{
    auto ptr = aes.encrypt(src, length);
    auto copy = new uint8_t[length];
    memcpy(copy, ptr, length);
    return copy;
}

uint8_t *CipherModule::decryptKey(uint8_t *src, long& length) 
{
    auto ptr = aes256->decrypt(src, length);
    auto copy = new uint8_t[length];
    memcpy(copy, ptr, length);
    return copy;
}

uint8_t* CipherModule::encryptKey(uint8_t* src, long& length)
{
    auto ptr = aes256->encrypt(src, length);
    auto copy = new uint8_t[length];
    memcpy(copy, ptr, length);
    return copy;
}