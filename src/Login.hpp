#pragma once
#include <string>
#include <memory>

#include "Sync.hpp"
#include "Cipher.hpp"

class LoginModule
{
private:
    std::shared_ptr<CipherModule> cipher;
    std::shared_ptr<SyncModule> sync;

    //So that the user does not have to enter them every single time
    std::string email;
    std::string password;

public:
    LoginModule(std::shared_ptr<SyncModule>& syncRef, std::shared_ptr<CipherModule>& cipherRef);

    bool login(const std::string& password);
    bool loginRemote(const std::string& email, const std::string& password);
    bool changePassword(const std::string& oldPassword, const std::string& newPassword);
    bool changeEmail(const std::string& password, const std::string& email);
    bool synchronize(void);
};