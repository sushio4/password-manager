#pragma once
#include <string>

#include "Sync.hpp"
#include "Cipher.hpp"

class LoginModule
{
private:
    CipherModule& cipher;
    SyncModule& sync;

public:
    LoginModule(SyncModule& syncMod, CipherModule& cipherMod);

    bool login(std::string password);
    bool changePassword(std::string oldPassword, std::string newPassword);
    bool changeEmail(std::string password, std::string email);
    bool synchronize(void);
};