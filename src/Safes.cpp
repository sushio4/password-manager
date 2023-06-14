#include "Safes.hpp"
#include <stdint.h>
#include <algorithm>

SafesModule::SafesModule(std::shared_ptr<SyncModule>& syncRef, std::shared_ptr<CipherModule>& cipherRef)
{
    sync = syncRef;
    cipher = cipherRef;
    readSafeListFile();
}

void SafesModule::postLoginInit()
{
    //to avoid nullptr dereferencing
    if(passFilePairs.size() != 0)
        readSafeFile(passFilePairs[0].second + ".safe");
}

bool SafesModule::isSafeOpen() const {return !!openSafe;}

bool SafesModule::areAnySafes() const {return passFilePairs.size() != 0;}

//will it work? who knows...
std::string SafesModule::getPassword(const std::string& name)
{
    auto encrypted = openSafe ? (*openSafe)[name] : std::pair{nullptr, 0};
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
    long length = encrypted.second;
    uint8_t* decrypted = cipher->decryptPassword(openSafe->cipherObjRef(), encrypted.first, length);

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

bool SafesModule::modifyPassword(const std::string& name, const std::vector<std::string>& data)
{
    long passLength = data[1].size();
    uint8_t* encryptedPassword = nullptr;
    if(passLength)
    {
        encryptedPassword = cipher->encryptPassword(openSafe->cipherObjRef(), (uint8_t*)data[1].c_str(), passLength);
        if(!encryptedPassword)
            return false;
    }

    for(auto p : passFilePairs)
    {
        if(name == p.first)
        {
            closeSafe();
            readSafeFile(p.second);
            p.first = data[0];
            return (openSafe->change(name, data[0], encryptedPassword, passLength) &&
                    writeSafeFile((std::string&)*openSafe + ".safe") &&
                    writeSafeListFile());
        }
    }

    return false;
}

bool SafesModule::addPassword(const std::string& safename, const std::vector<std::string>& data)
{
    if((!openSafe || (std::string&)(*openSafe) != safename) &&
        !readSafeFile(safename + ".safe"))   //this will exec only if the condition above is met
        return false;

    long passLength = data[1].size();
    auto encryptedPassword = cipher->encryptPassword(openSafe->cipherObjRef(), (uint8_t*)data[1].c_str(), passLength);
    if(!encryptedPassword)
        return false;

    passFilePairs.push_back({data[0], safename});

    return (openSafe->add(data[0], encryptedPassword, passLength) &&
            writeSafeFile((std::string&)*openSafe + ".safe") &&
            writeSafeListFile());
}

bool SafesModule::isInThatSafe(const std::string& passwordname)
{
    //Safe::operator[](const std::string&) returns {nullptr, 0} if it's not there
    return (bool)(*openSafe)[passwordname].first; 
}


bool SafesModule::changeSafeName(const std::string& safename, const std::string& newname)
{
    if((std::string&)(*openSafe) != safename &&
        !readSafeFile(safename + ".safe"))   //this will exec only if the condition above is met
        return false;

    (std::string&)(*openSafe) = newname;
    return true;
}

bool SafesModule::createSafe(const std::string& safename, AESType type)
{
    if(openSafe && !writeSafeFile((std::string&)(*openSafe) + ".safe")) return false;
    delete openSafe;

    openSafe = new Safe(safename, type);
    return writeSafeFile(safename + ".safe");
}

bool SafesModule::deleteSafe(const std::string& safename)
{
    bool res;
    if(safename == (std::string&)(*openSafe))
    {
        closeSafe();
        res = deleteSafeHelper(safename);
        if(passFilePairs.size())
            readSafeFile(passFilePairs[0].second);
        return res;
    }
    res = deleteSafeHelper(safename);
    if(passFilePairs.size())
        readSafeFile(passFilePairs[0].second);

    //cleanup
    for(auto i = passFilePairs.begin(); i < passFilePairs.end(); i++)
    {
        if(i->second == safename) 
        {
            passFilePairs.erase(i);
            i--;
        }
    }
    writeSafeListFile();
    
    return res;
}

bool SafesModule::deleteSafeHelper(const std::string& safename)
{
    if(!removeSafeFile(safename + ".safe")) return false;
    for(auto i = passFilePairs.begin(); i < passFilePairs.end(); i++)
    {
        if((*i).second == safename) passFilePairs.erase(i);
        i--;
    }
    return true;
}

bool SafesModule::deletePassword(const std::string& passwordName)
{
    if(!isInThatSafe(passwordName))
    {
        for(auto p : passFilePairs)
        {
            if(p.first == passwordName)
            {
                closeSafe();
                if(!readSafeFile(p.second + ".safe")) return false;
                goto found;
            }
            //not found
            return false;
        }
    }
    found:
    for(auto i = passFilePairs.begin(); i < passFilePairs.end(); i++)
        if((*i).first == passwordName)
        {
            passFilePairs.erase(i);
            break;
        }
    return openSafe->remove(passwordName) && writeSafeFile((std::string&)(*openSafe) + ".safe");
}