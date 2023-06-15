#include "Generator.hpp"
#include <cstring>
#include <ctime>

const char* asciiSet =  "qwertyuiopasdfghjklzxcvbnm"
                        "QWERTYUIOPASDFGHJKLZXCVBNM"
                        "1234567890" "!@#$%^&*()-_=+,./?";

const char* asciiPlusSet = "qwertyuiopasdfghjklzxcvbnm"
                        "QWERTYUIOPASDFGHJKLZXCVBNM"
                        "1234567890" "!@#$%^&*()-_=+,./?"
                        "`~[{]};:'\"\\|<>";

const char* alphanumSet = "qwertyuiopasdfghjklzxcvbnm"
                        "QWERTYUIOPASDFGHJKLZXCVBNM"
                        "1234567890";

const char* numericSet = "1234567890";

const char* letterSet = "qwertyuiopasdfghjklzxcvbnm"
                        "QWERTYUIOPASDFGHJKLZXCVBNM";



GeneratorModule::GeneratorModule(std::shared_ptr<SafesModule>& safesRef)
{
    safes = safesRef;
}

//added by 272234
std::string GeneratorModule::generate(const std::vector<std::string> &options) {
    //length, set [ascii|ascii+|alphanumeric|numeric|letters]
    std::string pwd = "";
    auto length = std::stoi(options[0]);
    if (length <= 0 || length > 32) return "";
    
    auto opt2 = options[1];
    char* set;

    if (opt2 == "ascii") set = (char*)asciiSet;
    else if (opt2 == "ascii+") set = (char*)asciiPlusSet;
    else if (opt2 == "alphanumeric") set = (char*)alphanumSet;
    else if (opt2 == "numeric") set = (char*)numericSet;
    else if (opt2 == "letters") set = (char*)letterSet;
    else return "";

    srand(time(0));
    for (int i = 0; i < length; i++)
    {
        pwd += set[ (rand() + i*i) % strlen(set) ];
    }
    return pwd;
}