#include "Safe.hpp"

Safe::Safe(AESType _type, uint8_t* _key, uint16_t _keyLength)
{
    type = _type;
    key = std::unique_ptr<uint8_t>(_key);
    keyLength = _keyLength;
}

Safe::~Safe()
{
    for(auto e : passwords) 
        delete[] e;
}

bool Safe::add(std::string&& name, uint8_t* password, uint8_t passwordLength)
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

uint32_t Safe::size()
{
    return passwords.size();
}

