#pragma once
#include <string>
#include <memory>
#include <vector>
#include <stdint.h>

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
    std::unique_ptr<AES> cipher;
    AESType type;
public:
    hackPrivate(names);
    hackPrivate(passwords);
    hackPrivate(cipher);
    hackPrivate(type);
};