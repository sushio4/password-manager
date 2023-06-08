
#include <iostream>
#include "../src/aes.cpp"

// rotWord and subWord set to public !

int main(){
    uint8_t key[16] = {0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64};

    // hello there mister, you cant :).
    uint8_t decryptedData[32] = {0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x20, 0x6d, 0x69, 0x73, 0x74, 0x65, 0x72, 0x2c, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x63, 0x61, 0x6e, 0x74, 0x20, 0x3a, 0x29, 0x2e};
    auto aes = AES128(32, key, nullptr, decryptedData );

    uint8_t testWord [4] = {0x11, 0x22, 0x33, 0x44};
    for(auto r: testWord){
        printf("%X ", r);
    }
    std::cout<<std::endl;
    aes.rotWord(testWord);
    for(auto t: testWord){
        printf("%X ", t);
    }

    return 0;
}