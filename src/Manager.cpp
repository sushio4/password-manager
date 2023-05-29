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

void Manager::getSafeList(std::vector<std::string>& list) const
{
    safes->getSafeList(list);
}

std::string Manager::readPassword(const std::string& safeName) 
{
    return safes->getDecryptedSafe(safeName);
}

std::string Manager::generatePassword(const std::vector<std::string>& args)
{
    return generator->generate(args);
}

bool Manager::existsSafe(const std::string& name)
{
    std::vector<std::string> list;
    safes->getSafeList(list);
    for(auto s : list)
        if(s == name) return true;
    return false;
}

bool Manager::editSafe(const std::string& safeName, const std::vector<std::string>& data)
{
    git
}