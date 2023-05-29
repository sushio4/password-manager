#pragma once
#include <string>
#include <memory>

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
    std::string name;
    std::unique_ptr<AES> cipher;
    AESType type;
public:
    hackPrivate(name);
    hackPrivate(cipher);
    hackPrivate(type);
};