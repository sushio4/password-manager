#include "Login.hpp"

LoginModule::LoginModule(std::shared_ptr<SyncModule>& syncRef, std::shared_ptr<CipherModule>& cipherRef)
{
    sync = syncRef;
    cipher = cipherRef;
}

//added by 272234
bool LoginModule::login(const std::string &password) {
    return true;
}

bool LoginModule::loginRemote(const std::string& email, const std::string& password){
    return true;
}

bool LoginModule::changePassword(const std::string& oldPassword, const std::string& newPassword){
    return true;
}

bool LoginModule::changeEmail(const std::string& password, const std::string& email){
    return true;
}

bool LoginModule::synchronize(void){
    return true;
}
