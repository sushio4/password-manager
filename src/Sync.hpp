#pragma once
#include <string>
#include <vector>

#include "Safe.hpp"

class SyncModule
{
private:
    std::string email, password;
    const std::string address;

public:
    SyncModule(void);

    void enterCredentials(std::string email, std::string password);
    bool isUpToDate(void);
    bool readSafes(std::vector<Safe>& safes);
    bool writeSafes(const std::vector<Safe>& safes);
    bool writeCredentials(std::string email, std::string password);
};