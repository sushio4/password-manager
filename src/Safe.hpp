#pragma once
#include <string>
#include <memory>

#include "aes.hpp"
#include "hack_private.hpp"

class Safe{
private:
    std::string name;
    std::unique_ptr<AES> cipher;
public:
    hackPrivate(name);
    hackPrivate(cipher);
};