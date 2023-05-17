#pragma once
#include <string>
#include <vector>

#include "Login.hpp"
#include "Safes.hpp"
#include "Generator.hpp"

class Manager
{
private:
    LoginModule& login;
    SafesModule& safes;
    GeneratorModule& generator;

    bool logged;

public:
    Manager(void);

    std::string getSafeList(void) const;
    std::string readPassword(const std::string& safeName);
    
    bool editSafe(const std::string& safeName, const std::vector<std::string>& data);
    bool newSafe(const std::vector<std::string>& data);

    bool login(std::string password);
    bool createRemoteAccount(std::string email, std::string password);
    bool changePassword(std::string oldPassword, std::string newPassword);
    bool changeEmail(std::string password, std::string email);
    bool synchronize(std::string email, std::string password);
};