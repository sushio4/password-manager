#include "aes.hpp"
// i hope that is for rand
#include <cstdlib>

// SECTION FOR MAIN AES CLASS

const uint8_t AES::SBOX[16][16] =
        { {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
          {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
          {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
          {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
          {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
          {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
          {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
          {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
          {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
          {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
          {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
          {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
          {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
          {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
          {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
          {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
        };

const uint8_t AES::INVSBOX[16][16] = {
        {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
        {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
        {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
        {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
        {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
        {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
        {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
        {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
        {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
        {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
        {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
        {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
        {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
        {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
        {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
        {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
};

// TWO LAST VALUES ARE WRONG - REPAIR LATER

const uint8_t AES::RCON[32] = {
        0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,
        0x1B,0x36,0x6C,0xD8,0xAB,0x4D,0x9A,0x2F,0x5E,
        0xBC,0x63,0xC6,0x97,0x35,0x6A,0xD4,0xB3,0x7D,
        0xFA,0xEF,0xC5, 0x00, 0x00
};

void AES::rotWord(uint8_t (&word)[4]){
    // <----- that way 0,1,2,3 becomes 1,2,3,0
    uint8_t buffer = word[0];
    for(int i = 0; i < 3; i++){
        word[i] = word[i+1];
    }
    word[3] = buffer;
}

// well actually i hope that will work
void AES::subWord(uint8_t (&word)[4]){
    for(auto &v : word){
        v = SBOX[v / 16][v % 16];
    }
}

void AES::invSubWord(uint8_t (&word)[4]){
    for(auto &v : word){
        v - INVSBOX[v / 16][v % 16];
    }
}

void AES::shiftRows(uint8_t (&chunk)[4][4]){
    // all rows at once from chunk not word
    for(int i = 1; i < 4; i++){
        for(int ii = 0; ii < i; ii++){
            uint8_t buffer = chunk[i][0];
            for(int iii = 0; iii < 3 ; iii++){
                chunk[i][iii] = chunk[i][iii+1];
            }
            chunk[i][3] = buffer;
        }
    }
}

// wait what the fuck is that code?
// I just wonder if the COLUMNS AND ROWS in this code are not messed up right now
void AES::invShiftRows(uint8_t (&chunk)[4][4]){
    for(int i = 1; i < 4 ;i++){
        // so the ii is amount of shifts
        for(int ii = 0; ii < i ; ii++){
            uint8_t buffer = chunk[i][3];
            for(int iii = 3; iii > 0 ; iii--){
                chunk[i][iii] = chunk[i][iii-1];
            }
            chunk[i][0] = buffer;
        }
    }
}

// that one static - well no idea what it does now
// probably will copy the code from some forgotte repo

// multiplication in GF helper actually - the whole purpose
uint8_t AES::mixColumnsMultiplicator(uint8_t bt, uint8_t mult){
    // there is a place of xtime lambda
    // multiplication in GF(256)
    // for now we will forget about that xtime
    // auto xtime = [auto x]{return ((x<<1) ^ (((x>>7) & 1) * 0x1b))};

    // state[0][c] = xtime(t[0]) ^ (t[1]) ^ xtime(t[1]) ^ (t[2]) ^ (t[3]);
    // state[1][c] = (t[0]) ^ xtime(t[1]) ^ (t[2]) ^ xtime(t[2]) ^ (t[3]);
    // state[2][c] = (t[0]) ^ (t[1]) ^ xtime(t[2]) ^ (t[3]) ^ xtime(t[3]);
    // state[3][c] = (t[0]) ^ xtime(t[0]) ^ (t[1]) ^ (t[2]) ^ xtime(t[3]);

    // chatGPT time to shine now
    // yeah I should probably by now know how the lambda above differ from the code below and make it my way, but too lazy

    // that function will multiply two numbers in GF 256
    // can be code with multiplication tables but those are huge

    uint8_t result = 0;
    uint8_t highBitSet;

    // mult is a polynominal parameter - a
    // bt is the value of x - b

    // but why should it be done 8 times?
    for (int i = 0; i < 8; i++) {
        if ((bt & 1) == 1) {
            result ^= mult;
        }

        // flag indicating that we supprassed the 256 GF limit
        highBitSet = (mult & 0x80);
        mult <<= 1;

        // it actually works somehow familiar to RCON values but to perform RCON with that function we would need a few more counters - varaibles
        if (highBitSet == 0x80) {
            mult ^= 0x1B; // XOR with the irreducible polynomial x^8 + x^4 + x^3 + x + 1
        }

        bt >>= 1;
    }

    return result;
}

void AES::mixColumns(uint8_t (&chunk)[4][4]){
    // YOU HAVE TO UNDERSTAND THAT CODE TO MAKE IT
    // static void MixColumns(state_t* state)
    // {
    //   uint8_t i;
    //   uint8_t Tmp, Tm, t;
    //   for (i = 0; i < 4; ++i)
    //   {
    //     t   = (*state)[i][0];
    //     Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    //     Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    //     Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    //     Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    //     Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
    //   }
    // }

    // well we will do it somehow similar
    // not sure if [number][i] or [i][number]
    // i think this is ok cuz COLUMNS

    uint8_t tmp[4][4];

    for(int i = 0; i < 4 ; i++){
        // not sure if that static_cast is needed either
        // remove and check later
        tmp[0][i] = static_cast<uint8_t>(mixColumnsMultiplicator(chunk[0][i], 2) ^ mixColumnsMultiplicator(chunk[1][i], 3) ^ chunk[2][i] ^ chunk[3][i]);
        tmp[1][i] = static_cast<uint8_t>(chunk[0][i] ^ mixColumnsMultiplicator(chunk[1][i], 2) ^ mixColumnsMultiplicator(chunk[2][i], 3) ^ chunk[3][i]);
        tmp[2][i] = static_cast<uint8_t>(chunk[0][i] ^ chunk[1][i] ^ mixColumnsMultiplicator(chunk[2][i], 2) ^ mixColumnsMultiplicator(chunk[3][i], 3));
        tmp[3][i] = static_cast<uint8_t>(mixColumnsMultiplicator(chunk[0][i], 3) ^ chunk[1][i] ^ chunk[2][i] ^ mixColumnsMultiplicator(chunk[3][i], 2));

        chunk[0][i] = tmp[0][i];
        chunk[1][i] = tmp[1][i];
        chunk[2][i] = tmp[2][i];
        chunk[3][i] = tmp[3][i];
    }

}

void AES::invMixColumns(uint8_t (&chunk)[4][4]){
    uint8_t tmp[4][4];

    // lets try no static cast here huh?
    for(int i = 0; i < 4; i++){
        tmp[0][i] = mixColumnsMultiplicator(chunk[0][i], 14) ^ mixColumnsMultiplicator(chunk[1][i], 11) ^ mixColumnsMultiplicator(chunk[2][i], 13) ^ mixColumnsMultiplicator(chunk[3][i], 9);

        tmp[1][i] = mixColumnsMultiplicator(chunk[0][i], 9) ^ mixColumnsMultiplicator(chunk[1][i], 14) ^ mixColumnsMultiplicator(chunk[2][i], 11) ^ mixColumnsMultiplicator(chunk[3][i], 13);

        tmp[2][i] = mixColumnsMultiplicator(chunk[0][i], 13) ^ mixColumnsMultiplicator(chunk[1][i], 9) ^ mixColumnsMultiplicator(chunk[2][i], 14) ^ mixColumnsMultiplicator(chunk[3][i], 11);

        tmp[3][i] = mixColumnsMultiplicator(chunk[0][i], 11) ^ mixColumnsMultiplicator(chunk[1][i], 13) ^ mixColumnsMultiplicator(chunk[2][i], 9) ^ mixColumnsMultiplicator(chunk[3][i], 14);

        chunk[0][i] = tmp[0][i];
        chunk[1][i] = tmp[1][i];
        chunk[2][i] = tmp[2][i];
        chunk[3][i] = tmp[3][i];
    }
}

// maybe we will drop from that idea
void AES::generateSalt(){

}

// well uint8_t* is not well suited for that operation - fuck
void AES::addPadding(){
    // uint8_t sizof is 1
    // I am not sure how to work on pointers tho
    uint8_t padding_val = 15 - dataLength % 16;
    for(int i = 0; i < padding_val ; i++){
        *(decryptedData + i) = padding_val;
    }
    dataLength += padding_val;
    // in my mind, in my head, this is working
}

void AES::removePadding(){
    // i believe this can be done that simple
    uint8_t padding_val = *(decryptedData + dataLength - 1);
    dataLength -= padding_val;
}

// AES128 CLASS SECTION

// AES128::AES128(long dataLength, uint8_t* key = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr){}

// i simply wonder if that kind of stuff will work
// if not try moving it into .hpp file (because it looks like it will not work)
AES128::AES128(long dataLength, uint8_t* key = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr){
    // haha that one i forced to be here :)
    this->dataLength = dataLength;
    // we will think about that -> what to do if not given and try to decode
    this->key = key;
    // ok that is what I need
    this->encryptedData = (encryptedData == nullptr) ? new uint8_t[this->dataLength + (16 - this->dataLength%16) % 16] : encryptedData;
    this->decryptedData = (decryptedData == nullptr) ? new uint8_t[this->dataLength + (16 - this->dataLength%16) % 16] : decryptedData;
}


// void AES128::expandKey(){
// segmentation fault - XD - not anymore :)
void AES128::expandKey(){
    // actually it will maybe return that expanded key huh?
    // ROUNDCOUNT * KEYLENGTH + 16 actually so maybe later change will be ok

    uint8_t tmp[4];
    //uint8_t expandedKey[176];

    for(int i = 0; i < 16 ; i++){
        expandedKey[i] = *(key+i);
    }


    // wait i am not sure how much of those I gatta make
    // i am not sure how to make it stop iterationg here
    // maybe will use while actually
    int i = 0;
    while(i < 160){
        // for(int i = 0; i < 160; ){
//        for(int ii = 0; ii < 4 ; ii++){
//            tmp[ii] = expandedKey[16 - 4 + i];
//        }
        for(auto &t : tmp){
            t = expandedKey[16 - 4 + i];
        }

        if(i % 16 == 0){
            uint8_t tmpAgain = tmp[0];
            for(int ii = 0; ii < 3 ; ii++){
                // tmp[ii] = tmp[ii+1];
                tmp[ii] = SBOX[tmp[ii+1]/16][tmp[ii+1]%16];
            }
            // tmp[3] = tmpAgain;
            tmp[3] = SBOX[tmpAgain/16][tmpAgain%16];

            // now it has to be xored with RCON
            tmp[0] ^= RCON[i/16];
        }

        for(int ii = 0; ii < 4 ; ii++){
            expandedKey[16 + i + ii] = tmp[ii] ^ expandedKey[i + ii];
        }
        i+=4;
    }
    // ok not sure how to return that either
//    ok lets say we return just a pointer
    //return expandedKey;
}

// here we just need some good randomization (use old one for now)
// should I make the key parameter set too?
//uint8_t* AES128::generateKey(){
//    uint8_t key[KEYLENGTH];
//    for (int i = 0; i < KEYLENGTH; i++) {
//        // key.push_back(std::byte(rand() % 256));
//        *(key + i) = rand() % 256;
//    }
//    // change later
//    return key;
//}

// ok so the encrypt method that works with self.key
// OPTIMIZATION NEEDED
uint8_t* AES128::encrypt(){
    // uint8_t* expandedKey = expandKey();
//    maybe make it faster by checking whether the expandedKey is generated already
    expandKey();
    uint8_t chunk[4][4];
    // so we need to delete the decryptedData in order to decrypt it once again or maybe just change the values

    // so either that
    // delete[] decryptedData;
    // decryptedData = encryptedData;
    // or that
    // another segmentation fault here - XD
    for(int i = 0; i < dataLength ; i++){
        *(encryptedData + i) = *(decryptedData + i);
    }

    // the round + last round (if before mix colums)
    for(int r = 1; r<=ROUNDCOUNT; r++){
        // i have alredy wrote that I have no idea how to for loop
        for(int i = 0; i < dataLength ; i+=16){
            // the round - well will figure out how many times
            // that is on word [4]
            for(int ii = 0 ; ii < 4 ; ii++){
                for(int iii = 0 ; iii < 4 ; iii++){
//                    chunk[i][ii] = *(encryptedData + i + ii*4 + iii);
                    chunk[ii][iii] = *(encryptedData + i + ii*4 + iii);
                }
//                ok so I see it sends it like a reference by default huh?
                subWord(chunk[ii]);
            }
            shiftRows(chunk);
            // for final round purposes
            if(r != ROUNDCOUNT) mixColumns(chunk);
            // addRoundKey and finish the round for chunk of data
            for(int ii = 0; ii < 4 ; ii++){
                for(int iii = 0; iii < 4 ; iii++){
                    *(encryptedData + i + ii*4 + iii) = chunk[ii][iii] ^ *(expandedKey + r*16 + ii*4 + iii);
                }
            }
        }
    }

    return encryptedData;
}

// for the sake of expandKey the encrypt with parameter will set private key variable and call standard encrypt() function :>
uint8_t* AES128::encrypt(uint8_t givenKey[16]){
    // i do not know if i should use self or not
//    no idea how c++ works
    key = givenKey;
    return encrypt();
}

uint8_t* AES128::decrypt(){
    // i believe the key expansion process is the same so...
//    oho so I had an expandedKey protected value :)
    // expandedKey = expandKey();

    expandKey();
    uint8_t chunk[4][4];
    // so we need to delete the decryptedData in order to decrypt it once again or maybe just change the values

    // so either that
    // delete[] decryptedData;
    // decryptedData = encryptedData;
    // or that

    for(int i = 0; i < dataLength ; i++){
        *(decryptedData + i) = *(encryptedData + i);
    }

    for(int r = 1 ; r <= ROUNDCOUNT; r++){
        // why is there -16 to dataLength?
        // and besides dataLength does not need to be n times 16 so ...
        // lets think about it
        // to work with dataLength like that we need padding mechanism fully functional
        for(int i = 0; i < dataLength ; i+=16){
            // addRoundKey step and reading to chunk
            for(int ii = 0 ; ii < 4 ; ii++){
                for(int iii = 0 ; iii < 4 ; iii++){
//                    the last iii was ii (dunno if that made sigkill)
                    chunk[ii][iii] = *(decryptedData + i + ii*4 + iii) ^ *(expandedKey + r*16 + ii*4 + iii);
                }
            }


            if(r != ROUNDCOUNT) invMixColumns(chunk);
//            got you bitch - segkill from here
            invShiftRows(chunk);

//            for(int ii = 0 ; ii < 4 ; ii++){
//                invSubWord(chunk[ii]);
//            }
            for(auto &c : chunk){
                invSubWord(c);
            }

            for(int ii = 0; ii < 4 ; ii++){
                for(int iii = 0; iii < 4 ; iii++){
//                    *(decryptedData + +i + ii*4 + iii) = chunk[ii][iii];
                    *(decryptedData + i + ii*4 + iii) = chunk[ii][iii];
                }
            }
        }
    }

    return decryptedData;
}

uint8_t* AES128::decrypt(uint8_t givenKey[16]){
    key = givenKey;
    return decrypt();
}


AES128CBC::AES128CBC(long dataLength, uint8_t* key = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr, uint8_t * iv = nullptr){}
uint8_t* AES128CBC::generateKey(){}
uint8_t* AES128CBC::encrypt(){}
uint8_t* AES128CBC::encrypt(uint8_t givenKey[16], uint8_t iv[16]){}
uint8_t* AES128CBC::decrypt(){}
uint8_t* AES128CBC::decrypt(uint8_t givenKey[16], uint8_t iv[16]){}

// AES192 CLASS SECTION

void AES192::expandKey(){}
AES192::AES192(long dataLength, uint8_t* key = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr){}
uint8_t* AES192::generateKey(){}
uint8_t* AES192::encrypt(){}
uint8_t* AES192::encrypt(uint8_t givenKey[24]){}
uint8_t* AES192::decrypt(){}
uint8_t* AES192::decrypt(uint8_t givenKey[24]){}

AES192CBC::AES192CBC(long dataLength, uint8_t* key = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr, uint8_t * iv = nullptr){}
uint8_t* AES192CBC::generateKey(){}
uint8_t* AES192CBC::encrypt(){}
uint8_t* AES192CBC::encrypt(uint8_t givenKey[24], uint8_t iv[16]){}
uint8_t* AES192CBC::decrypt(){}
uint8_t* AES192CBC::decrypt(uint8_t givenKey[24], uint8_t iv[16]){}

// AES256 CLASS SECTION

void AES256::expandKey(){}
AES256::AES256(long dataLength, uint8_t* key = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr){}
uint8_t* AES256::generateKey(){}
uint8_t* AES256::encrypt(){}
uint8_t* AES256::encrypt(uint8_t givenKey[32]){}
uint8_t* AES256::decrypt(){}
uint8_t* AES256::decrypt(uint8_t givenKey[32]){}

AES256CBC::AES256CBC(long dataLength, uint8_t* key = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr, uint8_t * iv = nullptr){}
uint8_t* AES256CBC::generateKey(){}
uint8_t* AES256CBC::encrypt(){}
uint8_t* AES256CBC::encrypt(uint8_t givenKey[32], uint8_t iv[16]){}
uint8_t* AES256CBC::decrypt(){}
uint8_t* AES256CBC::decrypt(uint8_t givenKey[32], uint8_t iv[16]){}