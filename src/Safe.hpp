#pragma once
#include <string>
#include <memory>
#include <vector>
#include <stdint.h>
#include <tuple>
#include <cstring>

#include "aes.hpp"
#include "hack_private.hpp"

enum AESType{
    AES_128,
    AES_192,
    AES_256,
    AES_128_CBC,
    AES_192_CBC,
    AES_256_CBC
};

class Safe{
private:
    std::vector<std::string> names;
    std::vector<uint8_t*> passwords;
    std::vector<uint8_t> passLengths;
    std::unique_ptr<AES> cipher;
    AESType type;
    std::unique_ptr<uint8_t> key;
    uint16_t keyLength;
public:
    Safe(AESType _type, uint8_t* _key, uint16_t _keyLength)
    {
        type = _type;
        key = std::unique_ptr<uint8_t>(_key);
        keyLength = _keyLength;
    }
    ~Safe() { for(auto e : passwords) delete[] e; }

    void add(std::string&& name, uint8_t* password, uint8_t passwordLength)
    {
        names.push_back(std::move(name));
        passwords.push_back(password);
        passLengths.push_back(passwordLength);
    }

    auto operator[](const std::string& name) -> std::pair<uint8_t*, uint8_t>
    {
        for(int i = 0; i < names.size(); i++)
            if(names[i] == name) return {passwords[i], passLengths[i]};
        return {nullptr, 0};
    }

    auto operator[](uint32_t index) -> std::tuple<std::string, uint8_t*, uint8_t>
    {
        return {names[index], passwords[index], passLengths[index]};
    }

    void getKeyInfo(uint8_t*& keyRef, uint16_t& lengthRef, AESType& type)
    {
        if(keyRef) delete[] keyRef;
        keyRef = new uint8_t[keyLength];
        lengthRef = keyLength;
        memcpy(keyRef, key.get(), keyLength);
    }

    uint32_t size()
    {
        return passwords.size();
    }
};