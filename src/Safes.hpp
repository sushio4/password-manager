#pragma once
#include <string>
#include <memory>

#include "Sync.hpp"
#include "Cipher.hpp"

#include "Safe.hpp"

class SafesModule
{
private:
    std::shared_ptr<CipherModule> cipher;
    std::shared_ptr<SyncModule> sync;

    Safe* open;


public:
    SafesModule(std::shared_ptr<SyncModule>& syncRef, std::shared_ptr<CipherModule>& cipherRef);

    const Safe& getSafe(std::string name);
    bool writeSafe(const Safe& safe, std::string name);
    bool synchronize(void);

private:
    bool openSafe(std::string name);
    void closeSafe(void);
};