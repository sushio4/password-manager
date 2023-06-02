#pragma once
#include <string>
#include <vector>
#include <memory>
#include <utility>

#include "Sync.hpp"
#include "Cipher.hpp"
#include "aes.hpp"
#include "Safe.hpp"

class SafesModule
{
private:
    std::shared_ptr<CipherModule> cipher;
    std::shared_ptr<SyncModule> sync;

    Safe* openSafe = nullptr;

    std::vector<std::pair<std::string, std::string>> passFilePairs; //{passwordname, filename}

public:
    SafesModule(std::shared_ptr<SyncModule>& syncRef, std::shared_ptr<CipherModule>& cipherRef);

    std::string getPassword(std::string name);
    void getPasswordList(std::vector<std::string>& list);    
    bool writePassword (const std::string& name, const std::vector<std::string>& data);
    bool addPassword(const std::vector<std::string>& data);
    bool synchronize(void);

private:
    bool readSafeListFile();
    bool writeSafeListFile();
    bool readSafeFile(const std::string& filename);
    bool writeSafeFile(const std::string& filename);
    bool removeSafeFile(const std::string& filename);
    void closeSafe(void);
};

/*
*   SPECIFICATION OF A SAFE FILE:
*
*   extension: .safe
*
*   structure:
*       - magic number 0x65666173 ("safe" in ascii)
*
*       - size of the encrypted key to the password (uint16_t)
*       - encrypted key to the passwords
*
*       - AES type (byte 0-5)
*
*       - number of passwords in a safe (int)
*       - passwords:
*           - null-terminated name
*           - size of encrypted password (byte)
*           - encrypted password
*
*
*   SPECIFICATION OF A SAFE LIST FILE:
*
*   extension: .sfls
*
*   strucutre:
*       - magic number 0x736C6673 ("sfls" in ascii)
*   
*       - number of entries (int)
*       - entries:
*           - password name
*           - ':'
*           - safe filename
*/