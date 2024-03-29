#include <iostream>
#include "../src/aes.cpp"

int main(){
    uint8_t key[32] = {0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64};
    
    uint8_t key2[24] = {0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64 };



    uint8_t decryptedData[32] = {0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x20, 0x6d, 0x69, 0x73, 0x74, 0x65, 0x72, 0x2c, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x63, 0x61, 0x6e, 0x74, 0x20, 0x3a, 0x29, 0x2e};

    uint8_t decryptedData2[24] = {0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x20, 0x6d, 0x69, 0x73, 0x74, 0x65, 0x72, 0x2c, 0x20, 0x79, 0x6f, 0x75, 0x20};

    // auto aes = AES256(32, key, nullptr, decryptedData2 );

    auto aes = AES192(24, key2, nullptr, decryptedData2 );

    // aes.expandKey();

    // printf("FIRST:\n");
    // for(int i = 0 ; i < 16; i++){
    //     for(int ii = 0 ; ii < 16 ; ii++){
    //         printf("%X ", aes.expandedKey[i + ii]);
    //     }
    //     printf("\n");
    // }

    printf("BEFORE:\n");
    for(auto d : decryptedData2){
        printf("%X ", d);
    }
    printf("\n");

    printf("here we try\n");
    uint8_t* enc = aes.encrypt();
    printf("segfault here?");

    printf("\n ENCRYPTED: \n");
    for(int i = 0 ; i < 32; i++){
        printf("%X ", enc[i]);
    }
    printf("\n");

    printf("\n--------------------\n");
    
    auto dec = aes.decrypt();

    printf("\n DECRYPTED: \n");
    for(int i = 0 ; i < 24 ; i++){
        printf("%X ", dec[i]);
    }
    printf("\n");

    return 0;
}