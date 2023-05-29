#pragma once
#include <vector>
#include <string>
#include <iostream>

#include "Manager.hpp"

#define checkArgNum(num, message) \
    if(vec.size() != num)\
    {\
        std::cout<<message;\
        return;\
    }

typedef std::vector<std::string> args_t;

void getGenArgs(args_t& args)
{
    std::string temp;
    std::cout << "Enter length: ";
    std::cin >> temp;
    args.push_back(temp);
    std::cout << "Enter character set [ascii|alphanumeric|numeric|letters]: ";
    std::cin >> temp;
    args.push_back(temp);
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
        std::cout << mgr.getSafeList() << std::endl;
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
        checkArgNum(4, "Usage: safe edit [name|password] <safename>\n");

        if(!mgr.existsSafe(vec[3]))
        {
            std::cout << "Safe named " << vec[3] << " does not exist.\n";
            return;
        }

        args_t data(2);

        if(vec[2] == "name")
        {
            std::cout << "Enter new name for this safe:\n";
            std::cin >> data[0];
            data[1] = mgr.readPassword(vec[3]);
        }
        else if(vec[2] == "password")
        {
            std::cout << "Enter new password for this safe (enter \"-\" to generate it):\n";
            std::cin >> data[1];
            data[0] = vec[3];

            if(data[1] == "-")
            {
                args_t args;
                getGenArgs(args);
                data[1] = mgr.generatePassword(args);
            }
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

        args_t data(2);
        data[0] = vec[2]; //name

        std::cout << "Enter a password for that safe (\"-\" to generate)\n";
        std::cin >> data[1];
        if(data[1] == "-")
        {
            args_t args;
            getGenArgs(args);
            data[1] = mgr.generatePassword(args);
        }
        mgr.newSafe(data);
    }
}

void synchronizeFunction(Manager& mgr, const args_t& vec)
{
    checkArgNum(3, "Usage: sync <email> <password>\n");

    if(mgr.synchronize(vec[1], vec[2]))
        std::cout << "Synchronized successfully!\n";
    else
        std::cout << "Could not synchronize. Check your credentials and/or internet connection.\n";
}