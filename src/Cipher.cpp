#include "Cipher.hpp"
#include <cstring>
#include <fstream>

uint8_t* CipherModule::makeKey(std::string password)
{
    //maybe it's not the safest, but it kinda works
    while(password.size() < 256/8) password += password; //artificially leghten it to fit the key length
    password.substr(0, 256/8); //truncate it to be exactly 256 bits
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
        std::ofstream valFile("val.bin");
        AES256 aes(11, masterKey, nullptr, (uint8_t*)"magic_value");
        auto encrypted = aes.encrypt();
        valFile << (char*)encrypted;
        valFile.close();
        return validated = true;
    }
    
    std::string encrypted;
    valFile >> encrypted;

    AES256 aes(11, masterKey, (uint8_t*)encrypted.c_str(), nullptr);
    std::string decrypted = (char*)aes.decrypt();

    return validated = (decrypted == "magic_value");
}
