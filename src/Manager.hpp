#pragma once
#include <string>
#include <vector>
#include <memory>

#include "Login.hpp"
#include "Safes.hpp"
#include "Generator.hpp"

class Manager
{
private:
    std::unique_ptr<LoginModule> login;
    std::unique_ptr<GeneratorModule> generator;
    std::shared_ptr<SafesModule> safes;

    bool logged;

public:
    Manager(void);

    std::string getSafeList(void) const;
    std::string readPassword(const std::string& safeName);
    
    bool existsSafe(const std::string& name);
    bool editSafe(const std::string& safeName, const std::vector<std::string>& data);
    bool newSafe(const std::vector<std::string>& data);

    bool loginLocal(std::string password);
    bool createRemoteAccount(std::string email, std::string password);
    bool changePassword(std::string oldPassword, std::string newPassword);
    bool changeEmail(std::string password, std::string email);
    bool synchronize(std::string email, std::string password);
};