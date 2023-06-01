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

    void getPasswordList(std::vector<std::string>& list) const;
    std::string readPassword(const std::string& safeName);
    std::string generatePassword(const std::vector<std::string>& args);
    
    bool existsPassword(const std::string& name);
    bool editPassword(const std::string& safeName, const std::vector<std::string>& data);
    bool newPassword(const std::vector<std::string>& data);

    bool loginLocal(const std::string& password);
    bool createRemoteAccount(const std::string& email, const std::string& password);
    bool changeLoginPassword(const std::string& oldPassword, const std::string& newPassword);
    bool changeEmail(const std::string& password, const std::string& email);
    bool loginRemote(const std::string& email, const std::string& password);
    bool synchronize(void);
};