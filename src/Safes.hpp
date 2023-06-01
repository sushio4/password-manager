#pragma once
#include <string>
#include <vector>
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

    std::string getDecryptedSafe(std::string name);
    void getSafeList(std::vector<std::string>& list);    
    bool writeSafe (const std::string& name, const std::vector<std::string>& data);
    bool createSafe(const std::vector<std::string>& data);
    bool synchronize(void);

private:
    bool openSafe(std::string name);
    void closeSafe(void);
};