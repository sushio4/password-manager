#pragma once
#include <string>

#include "Sync.hpp"
#include "Cipher.hpp"

#include "Safe.hpp"

class SafesModule
{
private:
    CipherModule& cipher;
    SyncModule& sync;

    Safe* open;


public:
    SafesModule(SyncModule& syncMod, CipherModule& cipherMod);

    const Safe& getSafe(std::string name);
    bool writeSafe(const Safe& safe, std::string name);
    bool synchronize(void);

private:
    bool openSafe(std::string name);
    void closeSafe(void);
};