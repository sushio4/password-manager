#pragma once
#include <vector>
#include <string>
#include <iostream>

#include "Manager.hpp"

typedef std::vector<std::string> args_t;

void inputGenArgs(args_t& args)
{
    std::string temp;
    std::cout << "Enter length:\n> ";
    std::cin >> temp;
    args.push_back(temp);
    std::cout << "Enter character set [ascii|ascii+|alphanumeric|numeric|letters]:\n> ";
    std::cin >> temp;
    args.push_back(temp);
}

bool inputPasswordName(std::string& name)
{
    std::cout << "Enter new name:\n> ";
    std::cin >> name;
    if(name == "")
    {
        std::cout << "Empty name not allowed!\n";
        return false;
    }
    return true;
}

bool inputPassword(std::string& password, Manager& mgr)
{
    std::cout << "Enter new password or \"-\" to have it generated for you (recommended):\n> ";
    std::cin >> password;
    
    if (password == "")
    {
        std::cout << "Why would you want to have an empty password?\n";
    }

    if (password != "-") return true;

    std::string s;
    args_t args;
    inputGenArgs(args);
    do
    {
        std::cout << "Your generated password:\n> " << (password = mgr.generatePassword(args)) << '\n';
        std::cout << "Enter \"r\" to regenerate or anything else to proceed\n> ";
        std::cin >> s;
    } while (s == "r");
}

bool inputAESType(uint8_t& type)
{
    std::cout << "Enter a number:\n"
        "0 - 128 bit\n"
        "1 - 192 bit\n"
        "2 - 256 bit\n"
        "3 - 128 with CBC\n"
        "4 - 192 with CBC\n"
        "5 - 256 with CBC\n> ";
    int itype;
    std::cin >> itype;
    if(itype < 0 || itype > 5)
    {
        std::cout << "Invalid option!\n";
        return false;
    }
    type = itype;
    return true;
}