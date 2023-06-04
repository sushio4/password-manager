#include "Safes.hpp"
#include <stdint.h>
#include <algorithm>

SafesModule::SafesModule(std::shared_ptr<SyncModule>& syncRef, std::shared_ptr<CipherModule>& cipherRef)
{
    sync = syncRef;
    cipher = cipherRef;
    readSafeListFile();
    //to avoid nullptr dereferencing
    readSafeFile(passFilePairs[0].second);
}

//will it work? who knows...
std::string SafesModule::getPassword(const std::string& name)
{
    auto encrypted = (*openSafe)[name];
    //if it's not in this safe, check where is it
    if(!encrypted.first)
    {
        std::string fname;
        for(auto p : passFilePairs)
            if (p.first == name)
            {
                fname = p.second;
                goto found;
            }
        return "";

        found:
        closeSafe();
        readSafeFile(fname);
        encrypted = (*openSafe)[name];
        if(!encrypted.first) return "Error that should not occur. List file lied about password's location!";
    }
    //decrypting
    uint8_t* decrypted = new uint8_t[encrypted.second];
    cipher->decryptPassword(openSafe->cipherObjRef(), encrypted.first, decrypted, encrypted.second);

    std::string password((const char*)decrypted);
    delete[] decrypted;

    return password;
}

void SafesModule::getPasswordList(std::vector<std::string>& list)
{
    list.clear();
    for(int i = 0; i < openSafe->size(); i++)
        list.push_back(std::get<0>((*openSafe)[i])); //(*openSafe)[i] returns tuple (name, encrypted password, length)
}

void SafesModule::getSafeList(std::vector<std::string>& list)
{
    list.clear();
    for(auto p : passFilePairs)
        if(std::find(list.begin(), list.end(), p.second) == list.end()) //if not already on the list
            list.push_back(p.second);
}

void SafesModule::getSafePasswordList(std::vector<std::string>& list)
{
    list.clear();
    for(auto p : passFilePairs)
        list.push_back(p.first + " : " + p.second);
}

bool SafesModule::isInThatSafe(const std::string& passwordname)
{
    //Safe::operator[](const std::string&) returns {nullptr, 0} if it's not there
    return (bool)(*openSafe)[passwordname].first; 
}