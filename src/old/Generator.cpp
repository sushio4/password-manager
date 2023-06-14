#include "Generator.hpp"

GeneratorModule::GeneratorModule(std::shared_ptr<SafesModule>& safesRef)
{
    safes = safesRef;
}