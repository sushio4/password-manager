#include "Manager.hpp"

Manager::Manager(void)
{
    auto sync = std::make_shared<SyncModule>();
    auto cipher = std::make_shared<CipherModule>();

    safes = std::make_shared<SafesModule>(sync, cipher);
    generator = std::make_unique<GeneratorModule>(safes);
    login = std::make_unique<LoginModule>(sync, cipher);

}