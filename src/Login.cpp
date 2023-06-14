#include "Login.hpp"

#include <fstream>

LoginModule::LoginModule(std::shared_ptr<SyncModule>& syncRef, std::shared_ptr<CipherModule>& cipherRef)
{
    sync = syncRef;
    cipher = cipherRef;
}

bool LoginModule::login(const std::string &password) {
    if(cipher->validatePassword(password))
    {
        this->password = password;
        return true;
    }
    return false;
}

bool LoginModule::loginRemote(const std::string& email, const std::string& password){
    return false;
}

bool LoginModule::changePassword(const std::string& oldPassword, const std::string& newPassword){
    return false;
}

bool LoginModule::changeEmail(const std::string& password, const std::string& email){
    return false;
}

bool LoginModule::synchronize(void){
    return false;
}

bool LoginModule::firstTime()
{
    return (!std::ifstream("val.bin"));
}