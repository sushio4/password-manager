#include "Generator.hpp"

GeneratorModule::GeneratorModule(std::shared_ptr<SafesModule>& safesRef)
{
    safes = safesRef;
}

//added by 272234
std::string GeneratorModule::generate(const std::vector<std::string> &options) {
    return "";
}