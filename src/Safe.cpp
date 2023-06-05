#include "Safe.hpp"

Safe::Safe(AESType _type, uint8_t* _key, uint16_t _keyLength)
{
    key = std::unique_ptr<uint8_t>(_key);
    keyLength = _keyLength;
    changeAES(_type);
}

Safe::~Safe()
{
    for(auto e : passwords) 
        delete[] e;
}

bool Safe::add(const std::string& name, uint8_t* password, uint8_t passwordLength)
{
    if((*this)[name].first) return false; //if the password already exists
    names.push_back(std::move(name));
    passwords.push_back(password);
    passLengths.push_back(passwordLength);
    return true;
}

bool Safe::change(const std::string& name, std::string newName, uint8_t* password, uint8_t passwordLength)
{
    if((*this)[newName].first) return false; //if the newName already exists

    for(int i = 0; i < names.size(); i++)
    {
        if(name == names[i])
        {
            if(newName != "") names[i] == newName;
            if(password && passwordLength) passwords[i] = password, passLengths[i] = passwordLength;
            return true;
        }
    }
    return false;
}

auto Safe::operator[](const std::string& name) -> std::pair<uint8_t*, uint8_t>
{
    for(int i = 0; i < names.size(); i++)
        if(names[i] == name) return {passwords[i], passLengths[i]};
    return {nullptr, 0};
}

auto Safe::operator[](uint32_t index) -> std::tuple<std::string, uint8_t*, uint8_t>
{
    return {names[index], passwords[index], passLengths[index]};
}

void Safe::getKeyInfo(uint8_t*& keyRef, uint16_t& lengthRef, AESType& type)
{
    if(keyRef) delete[] keyRef;
    keyRef = new uint8_t[keyLength];
    lengthRef = keyLength;
    memcpy(keyRef, key.get(), keyLength);
}

bool Safe::changeAES(AESType _type)
{
    type = _type;
    AES* ptr = nullptr;
    switch(type)
    {
    case AES_128:
        ptr = new AES128;
        break;
    case AES_192:
        ptr = new AES192;
        break;
    case AES_256:
        ptr = new AES256;
        break;
    case AES_128_CBC:
        ptr = new AES128CBC;
        break;
    case AES_192_CBC:
        ptr = new AES192CBC;
        break;
    case AES_256_CBC:
        ptr = new AES256CBC;
        break;
    default:
        return false;
        break;
    }
    cipher.reset(ptr);
    return true;
}

uint32_t Safe::size()
{
    return passwords.size();
}

