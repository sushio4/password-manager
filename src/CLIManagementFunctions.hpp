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

void quitFunction(Manager& mgr, const args_t& vec)
{
    std::exit(0);
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
        std::cout << "Usage: safe <command>\nAvailable commands:\n"
                    " - list [safes|passwords](optional)\n"
                    " - get <passwordname>\n"
                    " - edit [name|password] <passwordname>\n"
                    " - add <safename> <passwordname>\n"
                    " - change <safename>\n"
                    " - create\n";
        return;
    }

    if(!mgr.areAnySafes() && (vec[1] != "list") && (vec[1] != "create"))
    {
        std::cout << "You have no safes!\nEnter \"safe create\" to make one!\n";
        return;
    }

    if(vec[1] == "list")
    {
        args_t list;
        if(vec.size() == 2)
        {   
            std::cout << "All passwords:\n";
            mgr.getSafePasswordList(list);
        }
        else if(vec[2] == "safes")
        {
            std::cout << "Your safes:\n";
            mgr.getSafeList(list);
        }
        else if(vec[2] == "passwords")
        {
            if(!mgr.areAnySafes())
            {
                std::cout << "You have no safes!\nEnter \"safe create\" to make one!\n";
                return;
            }
            std::cout << "Passwords in a current safe:\n";
            mgr.getPasswordList(list);
        }
        else
        {
            std::cout << "Usage: safe list [safes|passwords](optional)\n";
            return;
        }

        if(list.size())
            for(auto e : list)
                std::cout << e << "\n";
        else 
            std::cout << "No elements!\n";
    }
    else if(vec[1] == "get")
    {
        checkArgNum(3, "Usage: safe get <passwordname>\n");

        auto res = mgr.readPassword(vec[2]);
        if(res == "")
            std::cout << "Password named " << vec[2] << " does not exist.\n";
        else
            std::cout << res << std::endl;
    }
    else if(vec[1] == "edit")
    {
        checkArgNum(4, "Usage: safe edit [name|password] <passwordname>\n");

        if(!mgr.existsPassword(vec[3]))
        {
            std::cout << "Password named " << vec[3] << " does not exist.\n";
            return;
        }

        args_t data(3);

        if(vec[2] == "name")
        {
            if(!inputPasswordName(data[0])) return;
        }
        else if(vec[2] == "password")
        {
            if(!inputPassword(data[1], mgr)) return;
        }

        if(!mgr.editPassword(vec[3], data));
            std::cout << "Could not edit that safe.\n";
    }
    else if(vec[1] == "add")
    {
        checkArgNum(4, "Usage: safe add <safename> <passwordname>\n");
        if(mgr.existsPassword(vec[2]))
        {
            std::cout << "Password already exists!\n";
            return;
        }

        args_t data(2);
        data[0] = vec[3]; //name

        if( !inputPassword(data[1], mgr) ) return;

        mgr.newPassword(vec[2], data);
    }
    else if(vec[1] == "change")
    {
        checkArgNum(3, "Usage: safe change <safename>\n");
        
        std::cout << "Enter new name:\n";
        std::string name;
        std::cin >> name;
        if(!mgr.changeSafeName(vec[3], name)) 
            std::cout << "Safe does not exist!\n";
    }
    else if(vec[1] == "create")
    {
        checkArgNum(2, "Usage: safe create");

        std::cout << "Enter a name for that safe:\n";
        std::string name;
        std::cin >> name;

        uint8_t type;
        if(!inputAESType(type)) return;

        if(!mgr.createSafe(name, type))
            std::cout << "Could not create safe!\n";
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