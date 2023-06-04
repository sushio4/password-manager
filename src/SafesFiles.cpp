#include "Safes.hpp"
#include <fstream>
#include <stdint.h>
#include <utility>
#include <cstdio>

void SafesModule::closeSafe()
{
    delete openSafe;
}

bool SafesModule::removeSafeFile(const std::string& filename)
{
    return !std::remove(filename.c_str());
}

bool SafesModule::readSafeFile(const std::string& filename)
{
    std::ifstream safeFile(filename, std::ios::in | std::ios::binary);
    if(!safeFile.is_open()) return false;

    //magic number check
    uint32_t magicNumber = 0;
    safeFile.read((char*)&magicNumber, 4);
    if(magicNumber != 0x65666173)
    {
        safeFile.close();
        return false;
    }

    uint16_t keySize = 0;
    uint8_t* encryptedKey;
    AESType type;
    uint32_t passNum;
    if(
        !safeFile.read((char*)&keySize, 1) |
        !(encryptedKey = new uint8_t[keySize]) | //not necessary but I want to keep read functions in that if
        !safeFile.read((char*)&encryptedKey, keySize) |
        !safeFile.read((char*)&type, 1) |
        !safeFile.read((char*)&passNum, 4)
    ){
        safeFile.close();
        if(encryptedKey) delete[] encryptedKey;
        return false;
    }

    auto decryptedKey = new uint8_t[keySize];
    AES256CBC aes;
    cipher->decryptKey(aes, encryptedKey, decryptedKey, keySize);
    delete[] encryptedKey;

    openSafe = new Safe(type, decryptedKey, keySize);

    for(int i = 0; i < passNum; i++)
    {
        char name[256];
        uint8_t *password;
        uint8_t passSize;

        if(
            !safeFile.getline(name, 255, '\0')  |
            !safeFile.read((char*)&passSize, 1) |
            !(password = new uint8_t[passSize]) | //not necessary but I want to keep read functions in that if
            !safeFile.read((char*)password, passSize)
        ){
            safeFile.close();
            delete openSafe;
            if(password) delete[] password;
            return false;
        }

        openSafe->add(name, password, passSize);
    }
    return true;
}

bool SafesModule::writeSafeFile(const std::string& filename)
{
    std::ofstream safeFile(filename, std::ios::out | std::ios::trunc | std::ios::binary);

    //magic number
    safeFile.write("safe", 4);

    uint16_t keySize;
    uint8_t* key;
    AESType type;
    openSafe->getKeyInfo(key, keySize, type);
    safeFile.write((char*)&keySize, 2);
    safeFile.write((char*)key, keySize);
    safeFile.write((char*)&type, 1);

    auto passNum = openSafe->size();
    safeFile.write((char*)&passNum, 4);

    for(int i = 0; i < passNum; i++)
    {
        auto element = (*openSafe)[i];
        safeFile << std::get<0>(element);
        safeFile.write((char*)&std::get<2>(element), 1);
        safeFile.write((char*)std::get<1>(element), std::get<2>(element));
    }
    return true;
}

bool SafesModule::readSafeListFile()
{
    std::ifstream listFile("safelist.sfls", std::ios::in | std::ios::binary);
    if(!listFile.is_open()) return false;

    //magic number check
    uint32_t magicNumber = 0;
    listFile.read((char*)&magicNumber, 4);
    if(magicNumber != 0x736C6673) 
    {
        listFile.close();
        return false;
    }

    uint32_t entriesNumber;
    listFile.read((char*)&entriesNumber, 4);

    passFilePairs.clear();

    for(int i = 0; i < entriesNumber; i++)
    {
        char readStr0[256];
        char readStr1[256];
        listFile.getline(readStr0, 256, ':');
        listFile.getline(readStr1, 256);

        if(! (*readStr0 * *readStr1)) 
        {
            listFile.close();
            return false; //empty string-> corrupted file
        }

        passFilePairs.push_back({readStr0, readStr1});
    }
    listFile.close();

    return true;
}

bool SafesModule::writeSafeListFile()
{
    std::ofstream listFile("safelist.sfls", std::ios::out | std::ios::trunc | std::ios::binary);

    //magic number
    listFile.write("sfls",4);

    uint32_t size = passFilePairs.size();
    listFile.write((char*)&size, 4);
    for(auto pair : passFilePairs)
    {
        listFile << pair.first;
        listFile << ':';
        listFile << pair.second;
        listFile << '\n';
    }
    listFile.close();

    return true;
}
