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
    auto res = std::remove(filename.c_str());
    return !res;
}

bool SafesModule::readSafeFile(const std::string& filename)
{
    if (openSafe) closeSafe();

    std::ifstream safeFile(filename, std::ios::in | std::ios::binary);
    if(!safeFile.is_open()) return false;

    //magic number check
    uint32_t magicNumber = 0;
    safeFile.read((char*)&magicNumber, 4);
    //safeFile >> magicNumber;
    if(magicNumber != 0x65666173)
    {
        safeFile.close();
        return false;
    }

    //std::string name;
    //safeFile >> name;
    char name[256];
    safeFile.getline(name, 256, '\0');

    long keySize = 0;
    uint8_t* encryptedKey = nullptr;

    uint16_t ivSize = 0;
    uint8_t* iv = nullptr;

    uint8_t typei;
    uint32_t passNum;

    //safeFile >> (int&)keySize;
    safeFile.read((char*)&keySize, sizeof(long));
    encryptedKey = new uint8_t[keySize+1];

    //for(int i = 0; i < keySize; i++)
    //    safeFile >> (int&)encryptedKey[i];
    safeFile.read((char*)encryptedKey, keySize);

    //safeFile >> (int&)ivSize;
    safeFile.read((char*)&ivSize, 2);
    if (ivSize)
    {
        iv = new uint8_t[ivSize];
        //for (int i = 0; i < ivSize; i++)
        //    safeFile >> (int&)iv[i];
        safeFile.read((char*)iv, ivSize);
    }    

    //safeFile >> (int&)typei;
    //safeFile >> (int&)passNum;
    safeFile.read((char*)&typei, 1);
    safeFile.read((char*)&passNum, 4);

    auto decryptedKey = cipher->decryptKey(encryptedKey, keySize);

    if(!ivSize) iv = nullptr;
    openSafe = new Safe(name, (AESType)typei, decryptedKey, iv);

    for(int i = 0; i < passNum; i++)
    {
        //std::string pname;
        char pname[256];
        uint8_t *password;
        uint8_t passSize;
    
        //safeFile >> pname;
        //safeFile >> (int&)passSize;
        safeFile.getline(pname, 256, '\0');
        safeFile.read((char*)&passSize, 1);

        password = new uint8_t[passSize];

        //for(int i = 0; i < passSize; i++)
        //    safeFile >> (int&)password[i];
        safeFile.read((char*)password, passSize);

        openSafe->add(pname, password, passSize);
    }
    safeFile.close();
    return true;
}

bool SafesModule::writeSafeFile(const std::string& filename)
{
    if(!openSafe) return true;
    std::ofstream safeFile(filename, std::ios::out | std::ios::trunc | std::ios::binary);

    //magic number
    //safeFile << 0x65666173 << '\n';
    uint32_t magic = 0x65666173;
    safeFile.write((char*)&magic, 4);

    auto name = (std::string&)(*openSafe);
    //safeFile << name << '\n';
    safeFile.write(name.c_str(), name.size()+1);

    long keySize;
    uint16_t keySize16;
    uint8_t* key = nullptr;
    uint16_t ivSize;
    uint8_t* iv = nullptr;
    AESType type;

    openSafe->getKeyInfo(key, keySize16, iv, ivSize, type);
    keySize = keySize16;
    auto encryptedKey = cipher->encryptKey(key, keySize);

    //safeFile << (int)keySize << '\n';
    safeFile.write((char*)&keySize, sizeof(long));

    //for(int i = 0; i < keySize; i++)
    //    safeFile << (int)encryptedKey[i] << '\n';
    safeFile.write((char*)encryptedKey, keySize);

    //safeFile << (int)ivSize << '\n';
    safeFile.write((char*)&ivSize, 2);
    
    if (ivSize)
    {
        safeFile.write((char*)iv, ivSize);
    }
    //for(int i = 0; i < ivSize; i++)
    //    safeFile << (int)iv[i] << '\n';

    //safeFile << (int)type << '\n';
    safeFile.write((char*)&type, 1);

    auto passNum = openSafe->size();
    //safeFile << passNum << '\n';
    safeFile.write((char*)&passNum, 4);

    for(int i = 0; i < passNum; i++)
    {
        auto element = (*openSafe)[i];
        auto name = std::get<0>(element);
        auto ptr  = std::get<1>(element);
        auto size = std::get<2>(element);
        //safeFile << name << '\n';
        safeFile.write(name.c_str(), name.size() + 1);
        //safeFile << (int)size << '\n';
        safeFile.write((char*)&size, 1);
        //for(int i = 0; i < size; i++)
        //    safeFile << (int)ptr[i] << '\n';
        safeFile.write((char*)ptr, size);
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

