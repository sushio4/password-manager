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

    bool logged = false;

public:
    Manager(void);

    bool firstTimeLog() const;
    void postLoginInit();

    void getPasswordList(std::vector<std::string>& list) const;
    void getSafeList(std::vector<std::string>& list) const;
    void getSafePasswordList(std::vector<std::string>& list) const;
    std::string readPassword(const std::string& passwordName);
    std::string generatePassword(const std::vector<std::string>& args);
    
    bool areSafesAvailable() const;
    
    bool existsPassword(const std::string& name);
    bool editPassword(const std::string& passwordName, const std::vector<std::string>& data);
    bool newPassword(const std::string& safename, const std::vector<std::string>& data);
    bool deletePassword(const std::string& passwordName);

    bool changeSafeName(const std::string& safename, const std::string& newname);
    bool createSafe(const std::string& safename, uint8_t type);
    bool deleteSafe(const std::string& safename);

    bool loginLocal(const std::string& password);
    bool createRemoteAccount(const std::string& email, const std::string& password);
    bool changeLoginPassword(const std::string& oldPassword, const std::string& newPassword);
    bool changeEmail(const std::string& password, const std::string& email);
    bool loginRemote(const std::string& email, const std::string& password);
    bool synchronize(void);
};