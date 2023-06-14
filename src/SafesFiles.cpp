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

    char name[256];
    safeFile.getline(name, 255, '\0');

    long keySize = 0;
    uint8_t* encryptedKey;

    uint16_t ivSize = 0;
    uint8_t* iv;

    uint8_t typei;
    uint32_t passNum;
    if(
        !safeFile.read((char*)&keySize, sizeof(long)) ||
        !(encryptedKey = new uint8_t[keySize]) || //not necessary but I want to keep read functions in that if
        !safeFile.read((char*)encryptedKey, keySize) ||

        !safeFile.read((char*)&ivSize, 2) ||
        !(iv = new uint8_t[ivSize]) ||
        !(safeFile.read((char*)iv, ivSize) || ivSize != 0) ||

        !safeFile.read((char*)&typei, 1) ||
        !safeFile.read((char*)&passNum, 4)
    ){
        safeFile.close();
        if(encryptedKey) delete[] encryptedKey;
        return false;
    }

    auto decryptedKey = cipher->decryptKey(encryptedKey, keySize);
    delete[] encryptedKey;

    openSafe = new Safe(name, (AESType)typei, decryptedKey, nullptr);

    for(int i = 0; i < passNum; i++)
    {
        char name[256];
        uint8_t *password;
        uint8_t passSize;

        if(
            !safeFile.getline(name, 255, '\0')  ||
            !safeFile.read((char*)&passSize, 1) ||
            !(password = new uint8_t[passSize]) || //not necessary but I want to keep read functions in that if
            !safeFile.read((char*)password, passSize)
        ){
            safeFile.close();
            delete openSafe;
            //delete[] password;
            return false;
        }

        openSafe->add(name, password, passSize);
    }
    safeFile.close();
    return true;
}

bool SafesModule::writeSafeFile(const std::string& filename)
{
    if(!openSafe) return true;
    std::ofstream safeFile(filename, std::ios::out | std::ios::trunc | std::ios::binary);

    //magic number
    safeFile.write("safe", 4);
    auto name = (std::string&)(*openSafe);
    safeFile.write(name.c_str(), name.size()+1);

    long keySize;
    uint16_t keySize16;
    uint8_t* key = nullptr;
    uint16_t ivSize;
    uint8_t* iv = nullptr;
    AESType type;

    openSafe->getKeyInfo(key, keySize16, iv, ivSize, type);
    keySize = keySize16;

    safeFile.write((char*)&keySize, sizeof(long));
    safeFile.write((char*)key, keySize);

    safeFile.write((char*)&ivSize, 2);
    safeFile.write((char*)iv, ivSize);

    safeFile.write((char*)&type, 1);

    auto passNum = openSafe->size();
    safeFile.write((char*)&passNum, 4);

    for(int i = 0; i < passNum; i++)
    {
        auto element = (*openSafe)[i];
        auto name = std::get<0>(element);
        safeFile.write(name.c_str(), name.size()+1);
        safeFile.write((char*)&std::get<2>(element), 1);
        safeFile.write((char*)std::get<1>(element), std::get<2>(element));
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

