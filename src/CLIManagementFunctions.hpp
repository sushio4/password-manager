#pragma once
#include <vector>
#include <string>
#include <iostream>

#include "Manager.hpp"
#include "CLIInputFunctions.hpp"

#define checkArgNum(num, message) \
    if(vec.size() != num)\
    {\
        std::cout<<message;\
        return;\
    }


void helpFunction(Manager& mgr, const args_t& vec)
{
    const char* helpStr = "\n"; //TODO: write an actual help message

    if(vec.size() == 0)
        std::cout << helpStr;
}

void loginFunction(Manager& mgr, const args_t& vec)
{
    checkArgNum(2, "Usage: login <password>\n");

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
        args_t list;
        mgr.getSafeList(list);
        for(auto e : list)
            std::cout << " - " << e << "\n";
    }
    else if(vec[1] == "get")
    {
        checkArgNum(3, "Usage: safe get <safename>\n");

        auto res = mgr.readPassword(vec[2]);
        if(res == "")
            std::cout << "Safe named " << vec[2] << " does not exist.\n";
        else
            std::cout << res << std::endl;
    }
    else if(vec[1] == "edit")
    {
        checkArgNum(4, "Usage: safe edit [name|password|AEStype] <safename>\n");

        if(!mgr.existsSafe(vec[3]))
        {
            std::cout << "Safe named " << vec[3] << " does not exist.\n";
            return;
        }

        args_t data(3);

        if(vec[2] == "name")
        {
            if(!inputSafeName(data[0])) return;
        }
        else if(vec[2] == "password")
        {
            if(!inputSafePassword(data[1], mgr)) return;
        }
        else if(vec[2] == "AEStype")
        {
            if(!inputSafeAESType(data[2])) return;
        }

        if(!mgr.editSafe(vec[3], data));
            std::cout << "Could not edit that safe.\n";
    }
    else if(vec[1] == "new")
    {
        checkArgNum(3, "Usage: safe new <safename>\n");
        if(mgr.existsSafe(vec[2]))
        {
            std::cout << "Safe already exists!\n";
            return;
        }

        args_t data(3);
        data[0] = vec[2]; //name

        if( !inputSafePassword(data[1], mgr) || 
            !inputSafeAESType (data[2])) return;

        mgr.newSafe(data);
    }
}

void synchronizeFunction(Manager& mgr, const args_t& vec)
{
    if(mgr.synchronize())
    {
        std::cout << "Synchronized successfully!\n";
        return;
    }
    
    std::cout << "Please enter your credentials.\nemail: ";
    std::string email, password;
    std::cin >> email;
    std::cout << "password: ";
    std::cin >> password;

    if(!mgr.loginRemote(email, password))
    {
        std::cout << "Could not log in. Check your credentials.\n";
        return;
    }

    if(!mgr.synchronize())
    {
        std::cout << "Synchronization failed. Check internet connection.\n";
        return;
    }

    std::cout << "Synchronization successfull!\n";
}