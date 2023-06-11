#include <iostream>
#include "../src/aes.cpp"

int main(){
    uint8_t key[16] = {0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64};



    uint8_t decryptedData[27] = {0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x20, 0x6d, 0x69, 0x73, 0x74, 0x65, 0x72, 0x2c, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x63, 0x61, 0x6e};

    uint8_t decryptedData2[16] = {0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x20, 0x6d, 0x69, 0x73, 0x74};

    auto aes = AES128(27, key, nullptr, decryptedData );

    // aes.expandKey();

    // printf("FIRST:\n");
    // for(int i = 0 ; i < 16; i++){
    //     for(int ii = 0 ; ii < 16 ; ii++){
    //         printf("%X ", aes.expandedKey[i + ii]);
    //     }
    //     printf("\n");
    // }

    printf("BEFORE:\n");
    for(auto d : decryptedData){
        printf("%X ", d);
    }
    printf("\n");

    uint8_t* enc = aes.encrypt();

    printf("\n ENCRYPTED: \n");
    for(int i = 0 ; i < 32; i++){
        printf("%X ", enc[i]);
    }
    printf("\n");

    printf("\n--------------------\n");
    
    auto dec = aes.decrypt();

    printf("\n DECRYPTED: \n");
    for(int i = 0 ; i < 27 ; i++){
        printf("%X ", dec[i]);
    }
    printf("\n");

    return 0;
}