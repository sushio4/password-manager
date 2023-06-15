//main file for cli program
#include <iostream>
#include <hash_map>
#include <cstring>
#include <exception>

// #include <vector>

#include "Manager.hpp"
// #include "Manager.cpp"
#include "CLIManagementFunctions.hpp"

#include <unordered_map>


typedef std::vector<std::string> args_t;
void getInput(args_t&);
void parseInput(Manager&, const args_t&);

int main(int argc, char* argv[])
{
    Manager manager;

    if(argc > 1)
    {
        //do stuff from args
    }
    else
    {
        args_t words;

        std::cout << "Password manager\n";
        if(manager.firstTimeLog())
        {
            loginFirstTime(manager);
        }
        else
        {
            std::string pwd;
            while(true){
                std::cout << "Please enter your password to log in:\n> ";
                std::cin >> pwd;
                if(manager.loginLocal(pwd))
                    break;
                std::cout << "Wrong password!\n";
            }
        }
        manager.postLoginInit();

        fflush(stdin);

        while(true)
        {
            std::cout << "Enter a command:\n> ";
            words.clear();
            getInput(words);        
            parseInput(manager, words);
        }
    }

    return 0;
}

void getInput(args_t& vec)
{
    char* line = nullptr;
    size_t count = 0;

    auto n = getline(&line, &count, stdin);
    while(n < 2) n = getline(&line, &count, stdin);
    line[n - 1] = ' ';
    
    auto token = strtok(line, " ");
    while(token != nullptr)
    {
        vec.push_back(std::string(token));
        token = strtok(NULL, " ");
    }
}

void parseInput(Manager& mgr, const args_t& vec)
{
    typedef void (*func_ptr)(Manager& mgr, const args_t& vec);
    //hashmap for efficiency
    const std::unordered_map<std::string, func_ptr> map = {
        {"help", helpFunction},
        {"login", loginFunction},
        {"safe", safeFunction},
        {"sync", synchronizeFunction},
        {"quit", quitFunction}
    };

    try{
        auto func = map.at(vec[0]);
        func(mgr, vec);
    } catch(std::exception& e)
    {
        helpFunction(mgr, vec);
    } 
}

