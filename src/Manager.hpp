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

    void getSafeList(std::vector<std::string>& list) const;
    std::string readPassword(const std::string& safeName);
    std::string generatePassword(const std::vector<std::string>& args);
    
    bool existsSafe(const std::string& name);
    bool editSafe(const std::string& safeName, const std::vector<std::string>& data);
    bool newSafe(const std::vector<std::string>& data);

    bool loginLocal(const std::string& password);
    bool createRemoteAccount(const std::string& email, const std::string& password);
    bool changePassword(const std::string& oldPassword, const std::string& newPassword);
    bool changeEmail(const std::string& password, const std::string& email);
    bool loginRemote(const std::string& email, const std::string& password);
    bool synchronize(void);
};