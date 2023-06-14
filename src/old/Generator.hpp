#pragma once
#include <string>
#include <vector>
#include <memory>

#include "Safes.hpp"

class GeneratorModule
{
private:
    std::shared_ptr<SafesModule> safes;

public:
    GeneratorModule(std::shared_ptr<SafesModule>& safesRef);

    std::string generate(const std::vector<std::string>& options);
};