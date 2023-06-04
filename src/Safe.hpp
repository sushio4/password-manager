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
    Safe(AESType _type, uint8_t* _key, uint16_t _keyLength);
    ~Safe();

    void add(std::string&& name, uint8_t* password, uint8_t passwordLength);

    auto operator[](const std::string& name) -> std::pair<uint8_t*, uint8_t>;
    auto operator[](uint32_t index) -> std::tuple<std::string, uint8_t*, uint8_t>;

    void getKeyInfo(uint8_t*& keyRef, uint16_t& lengthRef, AESType& type);

    uint32_t size();
};