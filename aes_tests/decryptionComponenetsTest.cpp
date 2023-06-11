#include <iostream>
#include "../src/aes.cpp"

// encnrypt set to public !

int main(){
    uint8_t key[16] = {0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64};

    // hello there mister, you cant :).
    uint8_t decryptedData[16] = {0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x20, 0x6d, 0x69, 0x73, 0x74};


    auto aes = AES128(16, key, nullptr, decryptedData );

    uint8_t chunk[4][4] = {
        {0x10, 0x11, 0x12, 0x13},
        {0x20, 0x21, 0x22, 0x23},
        {0x30, 0x31, 0x32, 0x33},
        {0x40, 0x41, 0x42, 0x43}
    };

    std::cout<<"BEFORE:\n";
    for(int i = 0; i < 4 ; i++){
        for(int ii = 0; ii < 4 ; ii++){
            printf("%x ", chunk[i][ii]);
        }
        printf("\n");
    }
    printf("\n");

    for(auto &c : chunk){
        aes.subWord(c);
    }

    std::cout<<"AFTER SUB WORD:\n";
    for(int i = 0; i < 4 ; i++){
        for(int ii = 0; ii < 4 ; ii++){
            printf("%x ", chunk[i][ii]);
        }
        printf("\n");
    }
    printf("\n");

    for(auto &c: chunk){
        aes.invSubWord(c);
    }

    std::cout<<"AFTER INV SUB WORD:\n";
    for(int i = 0; i < 4 ; i++){
        for(int ii = 0; ii < 4 ; ii++){
            printf("%x ", chunk[i][ii]);
        }
        printf("\n");
    }
    printf("\n");







    // mixColumns and invMixColumns

    // std::cout<<"BEFORE:\n";
    // for(int i = 0; i < 4 ; i++){
    //     for(int ii = 0; ii < 4 ; ii++){
    //         printf("%x ", chunk[i][ii]);
    //     }
    //     printf("\n");
    // }
    // printf("\n");

    // aes.mixColumns(chunk);

    // std::cout<<"MIX COLUMNS:\n";
    // for(int i = 0; i < 4 ; i++){
    //     for(int ii = 0; ii < 4 ; ii++){
    //         printf("%x ", chunk[i][ii]);
    //     }
    //     printf("\n");
    // }
    // printf("\n");
    
    // aes.invMixColumns(chunk);

    // std::cout<<"INV MIX COLUMNS:\n";
    // for(int i = 0; i < 4 ; i++){
    //     for(int ii = 0; ii < 4 ; ii++){
    //         printf("%x ", chunk[i][ii]);
    //     }
    //     printf("\n");
    // }
    // printf("\n");

    // aes.shiftRows(chunk);

    // std::cout<<"SHIFT ROWS:\n";
    // for(int i = 0; i < 4 ; i++){
    //     for(int ii = 0; ii < 4 ; ii++){
    //         printf("%x ", chunk[i][ii]);
    //     }
    //     printf("\n");
    // }
    // printf("\n");

    // aes.invShiftRows(chunk);

    // std::cout<<"INV SHIFT ROWS:\n";
    // for(int i = 0; i < 4 ; i++){
    //     for(int ii = 0; ii < 4 ; ii++){
    //         printf("%x ", chunk[i][ii]);
    //     }
    //     printf("\n");
    // }
    // printf("\n");

    // uint8_t* enc = aes.encrypt();

    // printf("ENCRYPTED:\n");

    // for(int i = 0; i < 16; i++){
    //     printf("%X ", enc[i]);
    // }

    // uint8_t * dec = aes.decrypt();

    // printf("\nDECRYPTED:\n");
    // for(int i = 0; i < 16 ; i++){
    //     printf("%X ", dec[i]);
    // }

    return 0;
}