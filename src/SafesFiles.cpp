#include "Safes.hpp"
#include <fstream>
#include <stdint.h>
#include <utility>
#include <cstdio>

void SafesModule::closeSafe()
{
    delete openSafe;
    openSafe = nullptr;
}

bool SafesModule::removeSafeFile(const std::string& filename)
{
    return !std::remove(filename.c_str());
}

bool SafesModule::readSafeFile(const std::string& filename)
{
    if(openSafe) closeSafe();

    std::ifstream safeFile(filename);
    if(!safeFile.is_open()) return false;

    //magic number check
    uint32_t magicNumber = 0;
    safeFile >> magicNumber;
    if(magicNumber != 0x65666173)
    {
        safeFile.close();
        return false;
    }

    std::string name;
    safeFile >> name;

    long keySize = 0;
    uint8_t* encryptedKey;

    uint16_t ivSize = 0;
    uint8_t* iv;

    uint32_t typei;
    uint32_t passNum;

    safeFile >> keySize;
    encryptedKey = new uint8_t[keySize];
    for(int i = 0; i < keySize; i++)
        safeFile >> encryptedKey[i];

    safeFile >> ivSize;
    iv = new uint8_t[ivSize];
    for(int i = 0; i < ivSize; i++)
        safeFile >> iv[i];

    safeFile >> typei;
    safeFile >> passNum;

    auto decryptedKey = cipher->decryptKey(encryptedKey, keySize);
    delete[] encryptedKey;

    if(!ivSize) iv = nullptr;
    openSafe = new Safe(name, (AESType)typei, decryptedKey, iv);

    for(int i = 0; i < passNum; i++)
    {
        std::string name;
        uint8_t *password;
        uint32_t passSize;

    
        safeFile >> name;
        safeFile >> passSize;
        password = new uint8_t[passSize];
        for(int i = 0; i < passSize; i++)
            safeFile >> password[i];

        openSafe->add(name, password, passSize);
    }
    safeFile.close();
    return true;
}

bool SafesModule::writeSafeFile(const std::string& filename)
{
    if(!openSafe) return true;
    std::ofstream safeFile(filename, std::ios::out | std::ios::trunc);

    //magic number
    safeFile << 0x65666173 << '\n';
    auto name = (std::string&)(*openSafe);
    safeFile << name << '\n';

    long keySize;
    uint16_t keySize16;
    uint8_t* key = nullptr;
    uint16_t ivSize;
    uint8_t* iv = nullptr;
    AESType type;

    openSafe->getKeyInfo(key, keySize16, iv, ivSize, type);
    keySize = keySize16;
    auto encryptedKey = cipher->encryptKey(key, keySize);

    safeFile << keySize << '\n';

    for(int i = 0; i < keySize; i++)
        safeFile << encryptedKey[i] << '\n';

    safeFile << ivSize << '\n';
    
    for(int i = 0; i < ivSize; i++)
        safeFile << iv[i] << '\n';

    safeFile << (int)type << '\n';

    auto passNum = openSafe->size();
    safeFile << passNum << '\n';

    for(int i = 0; i < passNum; i++)
    {
        auto element = (*openSafe)[i];
        auto name = std::get<0>(element);
        auto ptr  = std::get<1>(element);
        auto size = std::get<2>(element);
        safeFile << name << '\n';
        safeFile << (int)size << '\n';
        for(int i = 0; i < size; i++)
            safeFile << ptr[i] << '\n';
    }
    safeFile.close();
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

