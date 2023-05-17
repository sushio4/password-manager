#pragma once
#include <string>
#include <vector>

#include "Safes.hpp"

class GeneratorModule
{
private:
    SafesModule& safes;

public:
    GeneratorModule(SafesModule& safesMod);

    std::string generate(const std::vector<std::string>& options);
};