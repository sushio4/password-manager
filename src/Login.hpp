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

public:
    LoginModule(std::shared_ptr<SyncModule>& syncRef, std::shared_ptr<CipherModule>& cipherRef);

    bool login(std::string password);
    bool changePassword(std::string oldPassword, std::string newPassword);
    bool changeEmail(std::string password, std::string email);
    bool synchronize(void);
};