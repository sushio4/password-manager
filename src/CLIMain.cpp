//main file for cli program
#include <iostream>
#include <hash_map>
#include <cstring>

#include "Manager.hpp"
#include "CLIFunctions.hpp"


typedef std::vector<std::string> args_t;

int main(int argc, char* argv[])
{
    Manager manager;

    if(argc > 1)
    {
        //do stuff from args
    }
    else while(true)
    {
        //do stuff from stdin
        std::cout << "Password manager\nEnter a command:\n";

        args_t words;
        getInput(words);        

        parseInput(manager, words);
    }

    return 0;
}

void getInput(args_t& vec)
{
    char* line = nullptr;
    size_t count = 0;

    getline(&line, &count, stdin);
    
    auto token = strtok(line, " ");
    while(token)
    {
        vec.push_back(token);
        token = strtok(NULL, " ");
    }
}

void parseInput(Manager& mgr, const args_t& vec)
{
    typedef void (*func_ptr)(Manager& mgr, const std::vector<std::string>& vec);
    //hashmap for efficiency
    const std::unordered_map<std::string, func_ptr> map = {
        {"help", helpFunction},
        {"login", loginFunction},
        {"safe", safeFunction}
    };

    auto func = map.at(vec[0]);
    func(mgr, vec); 
}

