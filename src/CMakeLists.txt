cmake_minimum_required(VERSION 3.25)
project(untitled)

set(CMAKE_CXX_STANDARD 17)

add_executable(untitled CLIMain.cpp aes.cpp aes.hpp Cipher.cpp Cipher.hpp Generator.cpp Generator.hpp Login.cpp Login.hpp Manager.cpp Manager.hpp Safe.cpp Safe.hpp Safes.cpp Safes.hpp Sync.cpp Sync.hpp CLIInputFunctions.hpp CLIManagementFunctions.hpp hack_private.hpp SafesFiles.cpp)
