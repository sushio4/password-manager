#include "Manager.hpp"

Manager::Manager(void)
{
    auto sync = std::make_shared<SyncModule>();
    auto cipher = std::make_shared<CipherModule>();

    safes = std::make_shared<SafesModule>(sync, cipher);
    generator = std::make_unique<GeneratorModule>(safes);
    login = std::make_unique<LoginModule>(sync, cipher);

    logged = false;
}

void Manager::getPasswordList(std::vector<std::string>& list) const
{
    safes->getPasswordList(list);
}

std::string Manager::readPassword(const std::string& name) 
{
    return safes->getPassword(name);
}

std::string Manager::generatePassword(const std::vector<std::string>& args)
{
    return generator->generate(args);
}

bool Manager::existsPassword(const std::string& name)
{
    std::vector<std::string> list;
    safes->getPasswordList(list);
    for(auto s : list)
        if(s == name) return true;
    return false;
}

bool Manager::editPassword(const std::string& name, const std::vector<std::string>& data)
{
    return safes->writePassword(name, data);
}

bool Manager::newPassword(const std::vector<std::string>& data)
{
    return safes->addPassword(data);
}

bool Manager::loginLocal(const std::string& password)
{
    return login->login(password);
}

bool Manager::createRemoteAccount(const std::string& password, const std::string& email)
{
    return login->changeEmail(password, email);
}

bool Manager::changeLoginPassword(const std::string& oldPassword, const std::string& newPassword)
{
    return login->changePassword(oldPassword, newPassword);
}

bool Manager::changeEmail(const std::string& password, const std::string& email)
{
    return login->changeEmail(password, email);
}

bool Manager::loginRemote(const std::string& email, const std::string& password)
{
    return login->loginRemote(email, password);
}

bool Manager::synchronize(void)
{
    return login->synchronize();
}