#pragma once
#include <vector>
#include <string>

#include "Manager.hpp"

typedef std::vector<std::string> args_t;

void helpFunction(Manager& mgr, const args_t& vec)
{
    const char* helpStr = "\n"; //TODO: write an actual help message
    
    if(vec.size() == 0)
        std::cout << helpStr;
}

void loginFunction(Manager& mgr, const args_t& vec)
{
    if(vec.size() != 2)
    {
        std::cout << "Usage: login <password>\n";
        return;
    }

    if(mgr.loginLocal(vec[1]))
        std::cout << "Logged in successfully!\n";
    else
        std::cout << "Could not log in. Check your password.\n";
}

void safeFunction(Manager& mgr, const args_t& vec)
{
    if(vec.size() < 2)
    {
        std::cout << "Usage: safe <command>\n";
        return;
    }

    if(vec[1] == "list")
    {
        std::cout << mgr.getSafeList() << std::endl;
    }
}
