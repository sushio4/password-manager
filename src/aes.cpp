#include "aes.hpp"
#include <cstdlib>
#include <ctime>

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

void AES::subWord(uint8_t (&word)[4]){
    for(auto &v : word){
        v = SBOX[v / 16][v % 16];
    }
}

void AES::invSubWord(uint8_t (&word)[4]){
    for(auto &v : word){
        v = INVSBOX[v / 16][v % 16];
    }
}

// it actually shifts columns XD but works so stays
void AES::shiftRows(uint8_t (&chunk)[4][4]){
    // all rows at once from chunk not word
    for(int i = 1; i < 4; i++){
        for(int ii = 0; ii < i; ii++){
            uint8_t buffer = chunk[0][i];
            for(int iii = 0; iii < 3 ; iii++){
                chunk[iii][i] = chunk[iii+1][i];
            }
            chunk[3][i] = buffer;
        }
    }
}

void AES::invShiftRows(uint8_t (&chunk)[4][4]){
    for(int i = 1; i < 4 ;i++){
        // so the ii is amount of shifts
        for(int ii = 0; ii < i ; ii++){
            uint8_t buffer = chunk[3][i];
            for(int iii = 3; iii > 0 ; iii--){
                chunk[iii][i] = chunk[iii-1][i];
            }
            chunk[0][i] = buffer; 
        }
    }
}

// that one static - well no idea what it does now
// multiplication in GF helper actually - the whole purpose
uint8_t AES::mixColumnsMultiplicator(uint8_t bt, uint8_t mult){
    uint8_t result = 0;
    uint8_t highBitSet;

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

    uint8_t tmp[4][4];

    for(int i = 0; i < 4 ; i++){

        tmp[i][0] = mixColumnsMultiplicator(chunk[i][0], 2) ^ mixColumnsMultiplicator(chunk[i][1], 3) ^ chunk[i][2] ^ chunk[i][3];
        tmp[i][1] = chunk[i][0] ^ mixColumnsMultiplicator(chunk[i][1], 2) ^ mixColumnsMultiplicator(chunk[i][2], 3) ^ chunk[i][3];
        tmp[i][2] = chunk[i][0] ^ chunk[i][1] ^ mixColumnsMultiplicator(chunk[i][2], 2) ^ mixColumnsMultiplicator(chunk[i][3], 3);
        tmp[i][3] = mixColumnsMultiplicator(chunk[i][0], 3) ^ chunk[i][1] ^ chunk[i][2] ^ mixColumnsMultiplicator(chunk[i][3], 2);

        chunk[i][0] = tmp[i][0];
        chunk[i][1] = tmp[i][1];
        chunk[i][2] = tmp[i][2];
        chunk[i][3] = tmp[i][3];
    }

}

void AES::invMixColumns(uint8_t (&chunk)[4][4]){
    uint8_t tmp[4][4];

    // lets try no static cast here huh?
    for(int i = 0; i < 4; i++){
        tmp[i][0] = mixColumnsMultiplicator(chunk[i][0], 14) ^ mixColumnsMultiplicator(chunk[i][1], 11) ^ mixColumnsMultiplicator(chunk[i][2], 13) ^ mixColumnsMultiplicator(chunk[i][3], 9);

        tmp[i][1] = mixColumnsMultiplicator(chunk[i][0], 9) ^ mixColumnsMultiplicator(chunk[i][1], 14) ^ mixColumnsMultiplicator(chunk[i][2], 11) ^ mixColumnsMultiplicator(chunk[i][3], 13);

        tmp[i][2] = mixColumnsMultiplicator(chunk[i][0], 13) ^ mixColumnsMultiplicator(chunk[i][1], 9) ^ mixColumnsMultiplicator(chunk[i][2], 14) ^ mixColumnsMultiplicator(chunk[i][3], 11);

        tmp[i][3] = mixColumnsMultiplicator(chunk[i][0], 11) ^ mixColumnsMultiplicator(chunk[i][1], 13) ^ mixColumnsMultiplicator(chunk[i][2], 9) ^ mixColumnsMultiplicator(chunk[i][3], 14);

        chunk[i][0] = tmp[i][0];
        chunk[i][1] = tmp[i][1];
        chunk[i][2] = tmp[i][2];
        chunk[i][3] = tmp[i][3];
    }
}

// generateSalt renamed to addSalt !
void AES::addSalt(){
    srand(time(0));
    for (int i = 0; i < 16; i++) {
        *(this->encryptedData + i) = rand() % 256;
    }
}

// if we need that - it will be not void
void AES::removeSalt(){

}

// fuck me I have to make another array and point to it after data passgae
void AES::addPadding(){
    // uint8_t sizof is 1

    uint8_t paddingVal = (16 - decDataLength % 16);

    for(int i = 1; i <= paddingVal ; i++){

        *(encryptedData + this->encDataLength - 1 - paddingVal + i) = paddingVal;
    }
}

uint8_t* AES::encrypt(uint8_t* givenData, long& length)
{
    decryptedData = givenData;
    decDataLength = length;

    encDataLength = -1;
    auto res = encrypt();
    length = this->encDataLength;
    return res;
}

uint8_t* AES::decrypt(uint8_t* givenData, long& length)
{
    encryptedData = givenData;
    encDataLength = length;

    decDataLength = -1;
    auto res = decrypt();
    length = this->decDataLength;
    return res;
}

// AES128 CLASS SECTION


// another assumntion - you can provide only one: encrypted or decrypted data
// remember now there are two dataLength vars
AES128::AES128(long dataLength, uint8_t* key = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr){
    this->key = key;
    // ok encryptedData already have the slat and padding so if it is actually supplied it is ok

    // remember to provide only one of those below at a time - it is pointless to append two (maybe add antoher constructor in the future)

    if(encryptedData != nullptr){
        this->encDataLength = dataLength;
        this->decDataLength = -1;
    }else{
        this->decDataLength = dataLength;
        this->encDataLength = -1;
    }

    this->encryptedData = (encryptedData == nullptr) ? new uint8_t[dataLength + (((16 - dataLength%16) % 16) == 0 ? 16 : (16-dataLength%16))] : encryptedData;
    
    // ok we will assume that THERE IS NO PADDING AND SALT IN THE DECRYPTED DATA !!!!

    // dataLength -> another problem
    this->decryptedData = (decryptedData == nullptr) ? new uint8_t[dataLength] : decryptedData;
}


void AES128::expandKey(){
    // ROUNDCOUNT * KEYLENGTH + 16 actually so maybe later change will be ok
    uint8_t tmp[4];

    for(int i = 0; i < 16 ; i++){
        expandedKey[i] = *(key+i);
    }


    int i = 0;
    while(i < ROUNDCOUNT*16){
        for(int ii = 0; ii<4 ; ii++){
            // this might be inacurrate
            tmp[ii] = expandedKey[16 - 4 + ii + i];
        }

        if(i % 16 == 0){

            uint8_t tmpAgain = tmp[0];
            // subword on bytes
            for(int ii = 0; ii < 3 ; ii++){
                // why the fuck ii + 1? - so it was rotword and subword at once
                tmp[ii] = SBOX[tmp[ii+1]/16][tmp[ii+1]%16];
            }
            tmp[3] = SBOX[tmpAgain/16][tmpAgain%16];

            // xorwords and rcon 
            tmp[0] = tmp[0] ^ RCON[i/16 + 1];
        }

        for(int ii = 0; ii < 4 ; ii++){
            expandedKey[16 + i + ii] = tmp[ii] ^ expandedKey[i + ii];
        }
        i+=4;
    }
}

// well actually maybe that generate key only in AES?
uint8_t* AES128::generateKey(){
   auto key = new uint8_t[KEYLENGTH];
   srand(time(0));
   for (int i = 0; i < KEYLENGTH; i++) {
       *(key + i) = rand() % 256;
   }
   this->key = key;
   return key;
}

// ok so the encrypt method that works with self.key
// OPTIMIZATION NEEDED
uint8_t* AES128::encrypt(){
//    maybe make it faster by checking whether the expandedKey is generated already
    expandKey();
    uint8_t chunk[4][4];

    if(this->encDataLength == -1){
        this->encDataLength = this->decDataLength + ((16 - this->decDataLength % 16) == 0 ? 16 : (16 - this->decDataLength % 16));
    }

    // printf("\n%i\n",this->encDataLength);

    encryptedData = new uint8_t[encDataLength];

    for(int i = 0; i < this->decDataLength ; i++){
        *(encryptedData + i) = *(decryptedData + i);
    }

    // padding addition
    addPadding();

    // we are not adding salt in ECB

    // the round + last round (if before mix colums)
    for(int r = 1; r<=ROUNDCOUNT; r++){
        
        for(int i = 0; i < this->encDataLength ; i+=16){

            // here is the first iteration of data xored with begin key
            if(r == 1){
                for(int ii = i; ii < i+16 ; ii++){
                    *(encryptedData + ii) = *(encryptedData + ii) ^ *(key + ii%16);
                }
            }

            // the round - well will figure out how many times
            // that is on word [4]
            for(int ii = 0 ; ii < 4 ; ii++){
                for(int iii = 0 ; iii < 4 ; iii++){
                    chunk[ii][iii] = *(encryptedData + i + ii*4 + iii);
                }
                // ok so I see it sends it like a reference by default huh?
                subWord(chunk[ii]);
            }

            shiftRows(chunk);
            
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

uint8_t* AES128::encrypt(uint8_t givenKey[16]){
    this->key = givenKey;
    return encrypt();
}

uint8_t* AES128::decrypt(){
    expandKey();
    uint8_t chunk[4][4];

    // that makes a need for decDataLength be more than just the data 
    // ok here we will use the tmpData array
    // do not forget to del at the end

    uint8_t* tmpDataArray = new uint8_t[this->encDataLength];

    // from now on in decryption process we will use tmpDataArray (padding needs to be reoved before decryptedData

    for(int i = 0; i < this->encDataLength ; i++){
        *(tmpDataArray + i) = *(encryptedData + i);
    }

    // all of this has to be done on tmpDataArray now !!!

    for(int r = 1 ; r <= ROUNDCOUNT; r++){
        for(int i = 0; i < this->encDataLength ; i+=16){

            for(int ii = 0 ; ii < 4 ; ii++){
                for(int iii = 0 ; iii < 4 ; iii++){
                    chunk[ii][iii] = *(tmpDataArray + i + ii*4 + iii) ^ *(expandedKey + (ROUNDCOUNT + 1 - r)*16 + ii*4 + iii);
                }
            }


            if(r != 1) invMixColumns(chunk);
            invShiftRows(chunk);

            for(auto &c : chunk){
                invSubWord(c);
            }

            for(int ii = 0; ii < 4 ; ii++){
                for(int iii = 0; iii < 4 ; iii++){
                    *(tmpDataArray + i + ii*4 + iii) = chunk[ii][iii];
                }
            }
            // there the reverse of the first step from encryption
            if(r == ROUNDCOUNT){
                for(int ii = i; ii < i+16 ; ii++){
                    *(tmpDataArray + ii) = *(tmpDataArray + ii) ^ *(key + ii%16);
                }
            }
        }
    }


    // remove padding within a process of copying data from tmpDataArray to decryptedData
    if(this->decDataLength == -1){
        uint8_t paddingVal = *(tmpDataArray + this->encDataLength - 1);
        this->decDataLength = this->encDataLength - paddingVal;
    }


    // printf("\n%i\n",this->decDataLength);

    if(decDataLength <= 0 || decDataLength > encDataLength)
    {
        delete[] tmpDataArray;
        decDataLength = 0;
        return decryptedData = nullptr;
    }
    decryptedData = new uint8_t[decDataLength + 1];
    decryptedData[decDataLength] = '\0';

    for(int i = 0 ; i < this->decDataLength ; i++){

        *(decryptedData + i) = *(tmpDataArray + i);

    }

    delete[] tmpDataArray;

    return decryptedData;
}

uint8_t* AES128::decrypt(uint8_t givenKey[16]){
    this->key = givenKey;
    return decrypt();
}

// I really hope this will work :>
// it cannot work that way cuz fucking salt :<
AES128CBC::AES128CBC(long dataLength, uint8_t* key = nullptr, uint8_t* iv = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr) : AES128(dataLength, key, encryptedData, decryptedData){
    this->iv = iv;
}

// uint8_t* AES128CBC::generateKey(){}
uint8_t*  AES128CBC::generateIv(){
    // here I am gonna cheat a little
    // iv is 128 bit :>
    this->iv = generateKey();
    return this->iv;
}

// ok so encrypt works like the 128 with one difference (xor with previous block before the whole operation and the first block is xored with iv)
uint8_t* AES128CBC::encrypt(){
    expandKey();
    uint8_t chunk[4][4];

    // padding and salt 
    if(this->encDataLength == -1){
       this->encDataLength = this->decDataLength + 16 + ((16 - this->decDataLength % 16) == 0 ? 16 : (16 - this->decDataLength % 16));
    }

    encryptedData = new uint8_t[encDataLength];

    for(int i = 0; i < this->decDataLength ; i++){
        *(encryptedData + 16 + i) = *(decryptedData + i);
    }


    // padding and salt
    addPadding();
    addSalt();

    // first blokc outside the loop
    for(int i = 0 ; i < 16; i++){
        *(this->encryptedData + i) = *(this->encryptedData + i) ^ *(this->iv + i);
    }

    // we do not need any xoring with the key itself anymore in first round because of iv


    for(int r = 1; r<=ROUNDCOUNT; r++){
        for(int ii = 0 ; ii < 4 ; ii++){
            for(int iii = 0 ; iii < 4 ; iii++){
                chunk[ii][iii] = *(encryptedData + ii*4 + iii);
            }
            subWord(chunk[ii]);
        }

        shiftRows(chunk);
            
        if(r != ROUNDCOUNT) mixColumns(chunk);

        for(int ii = 0; ii < 4 ; ii++){
            for(int iii = 0; iii < 4 ; iii++){
                *(encryptedData + ii*4 + iii) = chunk[ii][iii] ^ *(expandedKey + r*16 + ii*4 + iii);
            }
        }
    }

    for(int i = 16 ; i < this->encDataLength; i+=16){

        // xor phase - CBC moments

        for(int ii = 0 ; ii < 16; ii++){
            *(this->encryptedData + i + ii) = *(this->encryptedData + i + ii) ^ *(this->encryptedData - 16 + i + ii);
        }

        // standard phase

        for(int r = 1; r <= ROUNDCOUNT; r++){
            
            for(int ii = 0 ; ii < 4 ; ii++){
                for(int iii = 0 ; iii < 4 ; iii++){
                    chunk[ii][iii] = *(encryptedData + i + ii*4 + iii);
                }
                subWord(chunk[ii]);
            }

            shiftRows(chunk);
            
            if(r != ROUNDCOUNT) mixColumns(chunk);

            for(int ii = 0; ii < 4 ; ii++){
                for(int iii = 0; iii < 4 ; iii++){
                    *(encryptedData + i + ii*4 + iii) = chunk[ii][iii] ^ *(expandedKey + r*16 + ii*4 + iii);
                }
            }
        }
    }

    return this->encryptedData;
}

uint8_t* AES128CBC::encrypt(uint8_t givenKey[16], uint8_t iv[16]){
    this->iv = iv;
    this->key = givenKey;
    return encrypt();
}

uint8_t* AES128CBC::decrypt(){
    expandKey();
    uint8_t chunk[4][4];

    uint8_t* tmpDataArray = new uint8_t[this->encDataLength];

    for(int i = 0 ; i < this->encDataLength ; i++){
        *(tmpDataArray + i) = *(encryptedData + i);
    }

    // all the dataBlocks excluding the first one
    // we will do i > 0 because of redundancy
    for(int i = this->encDataLength; i > 0; i-=16){

        // normal phase

        for(int r = 1 ;r <= ROUNDCOUNT; r++){

            for(int ii = 0 ; ii < 4 ; ii++){
                for(int iii = 0 ; iii < 4 ; iii++){
                    chunk[ii][iii] = *(tmpDataArray + i - 16 + ii*4 + iii) ^ *(expandedKey + (ROUNDCOUNT + 1 - r)*16 + ii*4 + iii);
                }
            }


            if(r != 1) invMixColumns(chunk);
            invShiftRows(chunk);

            for(auto &c : chunk){
                invSubWord(c);
            }

            for(int ii = 0; ii < 4 ; ii++){
                for(int iii = 0; iii < 4 ; iii++){
                    *(tmpDataArray - 16 + i + ii*4 + iii) = chunk[ii][iii];
                }
            }
        }

        // xor phase
        if(i > 16){
            for(int ii = 0 ; ii < 16; ii++){
                *(tmpDataArray + i - ii - 1) = *(tmpDataArray + i - ii - 1) ^ *(tmpDataArray - 16 + i - ii - 1);
            }
        }

    }

    for(int i = 0 ; i < 16; i++){
        *(tmpDataArray + i) = *(tmpDataArray + i) ^ *(this->iv + i);
    }

    // remove padding and slat within a process of copying data from tmpDataArray to decryptedData
    if(this->decDataLength == -1){
        uint8_t paddingVal = *(tmpDataArray + this->encDataLength - 1);
        this->decDataLength = this->encDataLength - paddingVal - 16;
    }

    if(decDataLength <= 0 || decDataLength > encDataLength)
    {
        delete[] tmpDataArray;
        decDataLength = 0;
        return decryptedData = nullptr;
    }
    decryptedData = new uint8_t[decDataLength + 1];
    decryptedData[decDataLength] = '\0';

    // for(int i = 16 ; i < this->decDataLength ; i++){
    //     *(this->decryptedData + i - 16) = *(tmpDataArray + i);
    // }

    for(int i = 0 ; i < this->decDataLength ; i++){
        *(this->decryptedData + i) = *(tmpDataArray + i + 16);
    }

    delete [] tmpDataArray;

    return this->decryptedData;
}

uint8_t* AES128CBC::decrypt(uint8_t givenKey[16], uint8_t iv[16]){
    this->iv = iv;
    this->key = givenKey;
    return decrypt();
}

// AES192 CLASS SECTION

void AES192::expandKey(){
    uint8_t tmp[4];
    for(int i = 0 ; i < KEYLENGTH; i++){
        expandedKey[i] = *(key + i);
    }
    int i = 0;

    // same as in 128 but with the gap of 6
    // ok we will do the standard 4 elements way - gap 6
    while(i < ROUNDCOUNT*16){
        for(int ii = 0; ii < 4; ii++){
            tmp[ii] = expandedKey[24 - 4 + ii + i];
        }

        if(i % 16 == 0){
            uint8_t tmpAgain = tmp[0];

            for(int ii = 0 ; ii < 3 ; ii++){
                tmp[ii] = SBOX[tmp[ii+1]/16][tmp[ii+1]%16];
            }

            tmp[3] = SBOX[tmpAgain/16][tmpAgain%16];

            tmp[0] = tmp[0] ^ RCON[i/16 + 1];
        }

        for(int ii = 0; ii < 4; ii ++){
            expandedKey[24 + i + ii] = tmp[ii] ^ expandedKey[i + ii];
        }
        i += 4;
    }
}


AES192::AES192(long dataLength, uint8_t* key = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr){
    this->key = key;
    // prepared for padding

    if(encryptedData != nullptr){
        this->encDataLength = dataLength;
        this->decDataLength = -1;
    }else{
        this->decDataLength = dataLength;
        this->encDataLength = -1;
    }

    this->encryptedData = (encryptedData == nullptr) ? new uint8_t[dataLength + (((16 - dataLength%16) % 16) == 0 ? 16 : (16-dataLength%16))] : encryptedData;
    
    // ok we will assume that THERE IS NO PADDING AND SALT IN THE DECRYPTED DATA !!!!

    // dataLength -> another problem
    this->decryptedData = (decryptedData == nullptr) ? new uint8_t[dataLength] : decryptedData;
}

uint8_t* AES192::generateKey(){
   auto key = new uint8_t[KEYLENGTH];
   srand(time(0));
   for (int i = 0; i < KEYLENGTH; i++) {
       // key.push_back(std::byte(rand() % 256));
       *(key + i) = rand() % 256;
   }
   this->key = key;
   return key;
}

uint8_t* AES192::encrypt(){
    expandKey();
    uint8_t chunk[4][4];

    if(this->encDataLength == -1){
        this->encDataLength = this->decDataLength + ((16 - this->decDataLength % 16) == 0 ? 16 : (16 - this->decDataLength % 16));
    }

    encryptedData = new uint8_t[encDataLength];

    for(int i = 0; i < this->decDataLength ; i++){
        *(encryptedData + i) = *(decryptedData + i);
    }

    addPadding();

    for(int r = 1; r<=ROUNDCOUNT; r++){
        
        for(int i = 0; i < this->encDataLength ; i+=16){

            // here is the first iteration of data xored with begin key
            if(r == 1){
                for(int ii = i; ii < i+16 ; ii++){
                    *(encryptedData + ii) = *(encryptedData + ii) ^ *(key + ii%16);
                }
            }

            // that is on word [4]
            for(int ii = 0 ; ii < 4 ; ii++){
                for(int iii = 0 ; iii < 4 ; iii++){
                    chunk[ii][iii] = *(encryptedData + i + ii*4 + iii);
                }
                subWord(chunk[ii]);
            }

            shiftRows(chunk);
            
            if(r != ROUNDCOUNT) mixColumns(chunk);

            // addRoundKey and finish the round for chunk of data
            for(int ii = 0; ii < 4 ; ii++){
                for(int iii = 0; iii < 4 ; iii++){
                    *(encryptedData + i + ii*4 + iii) = chunk[ii][iii] ^ *(expandedKey + 8 + r*16 + ii*4 + iii);
                }
            }
        }
    }
    return encryptedData;
}

uint8_t* AES192::encrypt(uint8_t givenKey[24]){
    this->key = givenKey;
    return encrypt();
}

uint8_t* AES192::decrypt(){
    expandKey();
    uint8_t chunk[4][4];

    // we are going to use tmpDataArray again here

    uint8_t* tmpDataArray = new uint8_t[this->encDataLength];

    for(int i = 0; i < this->encDataLength ; i++){
        // *(decryptedData + i) = *(encryptedData + i);
        *(tmpDataArray + i) = *(encryptedData + i);
    }

    for(int r = 1 ; r <= ROUNDCOUNT; r++){
        for(int i = 0; i < this->encDataLength ; i+=16){

            for(int ii = 0 ; ii < 4 ; ii++){
                for(int iii = 0 ; iii < 4 ; iii++){
                    chunk[ii][iii] = *(tmpDataArray + i + ii*4 + iii) ^ *(expandedKey + 8 + (ROUNDCOUNT + 1 - r)*16 + ii*4 + iii);
                }
            }


            if(r != 1) invMixColumns(chunk);
            invShiftRows(chunk);

            for(auto &c : chunk){
                invSubWord(c);
            }

            for(int ii = 0; ii < 4 ; ii++){
                for(int iii = 0; iii < 4 ; iii++){
                    *(tmpDataArray + i + ii*4 + iii) = chunk[ii][iii];
                }
            }
            // there the reverse of the first step from encryption
            if(r == ROUNDCOUNT){
                for(int ii = i; ii < i+16 ; ii++){
                    *(tmpDataArray + ii) = *(tmpDataArray + ii) ^ *(key + ii%16);
                }
            }
        }
    }

    // remove padding within a process of copying data from tmpDataArray to decryptedData
    if(this->decDataLength == -1){
        uint8_t paddingVal = *(tmpDataArray + this->encDataLength - 1);
        this->decDataLength = this->encDataLength - paddingVal;
    }

    
    if(decDataLength <= 0 || decDataLength > encDataLength)
    {
        delete[] tmpDataArray;
        decDataLength = 0;
        return decryptedData = nullptr;
    }
    decryptedData = new uint8_t[decDataLength + 1];
    decryptedData[decDataLength] = '\0';

    for(int i = 0 ; i < this->decDataLength ; i++){

        *(decryptedData + i) = *(tmpDataArray + i);

    }

    delete [] tmpDataArray;

    return decryptedData;
}

uint8_t* AES192::decrypt(uint8_t givenKey[24]){
    this->key = givenKey;
    return decrypt();
}


AES192CBC::AES192CBC(long dataLength, uint8_t* key = nullptr, uint8_t* iv = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr) : AES192(dataLength, key, encryptedData, decryptedData){
    this->iv = iv;
}

uint8_t* AES192CBC::generateIv(){
    srand(time(0));
    if(!iv) iv = new uint8_t[128/8];
    for(int i = 0 ; i < 16; i++){
        *(this->iv + i) = rand() % 256;
    }
    return this->iv;
}

uint8_t* AES192CBC::encrypt(){
    expandKey();
    uint8_t chunk[4][4];

    // padding and salt 
    if(this->encDataLength == -1){
       this->encDataLength = this->decDataLength + 16 + ((16 - this->decDataLength % 16) == 0 ? 16 : (16 - this->decDataLength % 16));
    }

    encryptedData = new uint8_t[encDataLength];

    for(int i = 0; i < this->decDataLength ; i++){
        *(encryptedData + 16 + i) = *(decryptedData + i);
    }

    // padding and salt
    addPadding();
    addSalt();

    // first blokc outside the loop
    for(int i = 0 ; i < 16; i++){
        *(this->encryptedData + i) = *(this->encryptedData + i) ^ *(this->iv + i);
    }

    // we do not need any xoring with the key itself anymore in first round because of iv


    for(int r = 1; r<=ROUNDCOUNT; r++){
        for(int ii = 0 ; ii < 4 ; ii++){
            for(int iii = 0 ; iii < 4 ; iii++){
                chunk[ii][iii] = *(encryptedData + ii*4 + iii);
            }
            subWord(chunk[ii]);
        }

        shiftRows(chunk);
            
        if(r != ROUNDCOUNT) mixColumns(chunk);

        for(int ii = 0; ii < 4 ; ii++){
            for(int iii = 0; iii < 4 ; iii++){
                *(encryptedData + ii*4 + iii) = chunk[ii][iii] ^ *(expandedKey + 8 + r*16 + ii*4 + iii);
            }
        }
    }

    for(int i = 16 ; i < this->encDataLength; i+=16){

        // xor phase - CBC moments

        for(int ii = 0 ; ii < 16; ii++){
            *(this->encryptedData + i + ii) = *(this->encryptedData + i + ii) ^ *(this->encryptedData - 16 + i + ii);
        }

        // standard phase

        for(int r = 1; r <= ROUNDCOUNT; r++){
            
            for(int ii = 0 ; ii < 4 ; ii++){
                for(int iii = 0 ; iii < 4 ; iii++){
                    chunk[ii][iii] = *(encryptedData + i + ii*4 + iii);
                }
                subWord(chunk[ii]);
            }

            shiftRows(chunk);
            
            if(r != ROUNDCOUNT) mixColumns(chunk);

            for(int ii = 0; ii < 4 ; ii++){
                for(int iii = 0; iii < 4 ; iii++){
                    *(encryptedData + i + ii*4 + iii) = chunk[ii][iii] ^ *(expandedKey + 8 + r*16 + ii*4 + iii);
                }
            }
        }
    }

    return this->encryptedData;
}

uint8_t* AES192CBC::encrypt(uint8_t givenKey[24], uint8_t iv[16]){
    this->iv = iv;
    this->key = givenKey;
    return encrypt();
}

uint8_t* AES192CBC::decrypt(){
    expandKey();
    uint8_t chunk[4][4];

    uint8_t* tmpDataArray = new uint8_t[this->encDataLength];

    for(int i = 0 ; i < this->encDataLength ; i++){
        *(tmpDataArray + i) = *(encryptedData + i);
    }

    // all the dataBlocks excluding the first one
    // we will do i > 0 because of redundancy
    for(int i = this->encDataLength; i > 0; i-=16){

        // normal phase

        for(int r = 1 ;r <= ROUNDCOUNT; r++){

            for(int ii = 0 ; ii < 4 ; ii++){
                for(int iii = 0 ; iii < 4 ; iii++){
                    chunk[ii][iii] = *(tmpDataArray + i - 16 + ii*4 + iii) ^ *(expandedKey + 8 + (ROUNDCOUNT + 1 - r)*16 + ii*4 + iii);
                }
            }


            if(r != 1) invMixColumns(chunk);
            invShiftRows(chunk);

            for(auto &c : chunk){
                invSubWord(c);
            }

            for(int ii = 0; ii < 4 ; ii++){
                for(int iii = 0; iii < 4 ; iii++){
                    *(tmpDataArray - 16 + i + ii*4 + iii) = chunk[ii][iii];
                }
            }
        }

        // xor phase
        if(i > 16){
            for(int ii = 0 ; ii < 16; ii++){
                *(tmpDataArray + i - ii - 1) = *(tmpDataArray + i - ii - 1) ^ *(tmpDataArray - 16 + i - ii - 1);
            }
        }

    }

    // xor with iv
    for(int i = 0 ; i < 16; i++){
        *(tmpDataArray + i) = *(tmpDataArray + i) ^ *(this->iv + i);
    }

    // remove salt and padding
    if(this->decDataLength == -1){
        uint8_t paddingVal = *(tmpDataArray + this->encDataLength - 1);
        this->decDataLength = this->encDataLength - paddingVal - 16;
    }
    
    if(decDataLength <= 0 || decDataLength > encDataLength)
    {
        delete[] tmpDataArray;
        decDataLength = 0;
        return decryptedData = nullptr;
    }
    decryptedData = new uint8_t[decDataLength + 1];
    decryptedData[decDataLength] = '\0';

    // for(int i = 16 ; i < this->decDataLength ; i++){
    //     *(this->decryptedData + i - 16) = *(tmpDataArray + i);
    // }

    for(int i = 0 ; i < this->decDataLength ; i++){
        *(this->decryptedData + i) = *(tmpDataArray + i + 16);
    }

    delete [] tmpDataArray;

    return this->decryptedData;
}

uint8_t* AES192CBC::decrypt(uint8_t givenKey[24], uint8_t iv[16]){
    this->iv = iv;
    this->key = givenKey;
    return decrypt();
}

// // AES256 CLASS SECTION

AES256::AES256(long dataLength, uint8_t* key = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr){

    this->key = key;

    if(encryptedData != nullptr){
        this->encDataLength = dataLength;
        this->decDataLength = -1;
    }else{
        this->decDataLength = dataLength;
        this->encDataLength = -1;
    }

    this->encryptedData = (encryptedData == nullptr) ? new uint8_t[dataLength + (((16 - dataLength%16) % 16) == 0 ? 16 : (16-dataLength%16))] : encryptedData;
    
    // ok we will assume that THERE IS NO PADDING AND SALT IN THE DECRYPTED DATA !!!!

    // dataLength -> another problem
    this->decryptedData = (decryptedData == nullptr) ? new uint8_t[dataLength] : decryptedData;
}

// I am not sure if that is the right way here
// look fine to me
void AES256::expandKey(){
    // ROUNDCOUNT * KEYLENGTH + 16 actually so maybe later change will be ok
    uint8_t tmp[4];

    for(int i = 0; i < KEYLENGTH ; i++){
        expandedKey[i] = *(key+i);
    }


    int i = 0;
    while(i < ROUNDCOUNT * 16){
        for(int ii = 0; ii<4 ; ii++){
            // this might be inacurrate
            tmp[ii] = expandedKey[32 - 4 + ii + i];
        }

        if(i % 16 == 0){

            uint8_t tmpAgain = tmp[0];
            // subword on bytes
            for(int ii = 0; ii < 3 ; ii++){
                // why the fuck ii + 1? - so it was rotword and subword at once
                tmp[ii] = SBOX[tmp[ii+1]/16][tmp[ii+1]%16];
            }
            tmp[3] = SBOX[tmpAgain/16][tmpAgain%16];

            // xorwords and rcon 
            tmp[0] = tmp[0] ^ RCON[i/16 + 1];
        }

        for(int ii = 0; ii < 4 ; ii++){
            expandedKey[32 + i + ii] = tmp[ii] ^ expandedKey[i + ii];
        }
        i+=4;
    }
}

// for later thoughts
uint8_t* AES256::generateKey(){
   auto key = new uint8_t[KEYLENGTH];
   srand(time(0));
   for (int i = 0; i < KEYLENGTH; i++) {
       *(key + i) = rand() % 256;
   }
   this->key = key;
   return key;
}

uint8_t* AES256::encrypt(){
    expandKey();
    uint8_t chunk[4][4];

    if(this->encDataLength == -1){
        
        this->encDataLength = this->decDataLength + ((16 - this->decDataLength % 16) == 0 ? 16 : (16 - this->decDataLength % 16));
    }

    encryptedData = new uint8_t[encDataLength];

    for(int i = 0; i < this->decDataLength ; i++){
        *(encryptedData + i) = *(decryptedData + i);
    }

    addPadding();

    for(int r = 1; r<=ROUNDCOUNT; r++){
        for(int i = 0; i < this->encDataLength; i+= 16){

            // here is the first iteration of data xored with begin key
            if(r == 1){
                for(int ii = i; ii < i+16 ; ii++){
                    *(encryptedData + ii) = *(encryptedData + ii) ^ *(key + ii%16);
                }
            }

            // that is on word [4]
            for(int ii = 0 ; ii < 4 ; ii++){
                for(int iii = 0 ; iii < 4 ; iii++){
                    chunk[ii][iii] = *(encryptedData + i + ii*4 + iii);
                }
                subWord(chunk[ii]);

            }

            shiftRows(chunk);

            if(r != ROUNDCOUNT) mixColumns(chunk);


            // addRoundKey and finish the round for chunk of data
            for(int ii = 0; ii < 4 ; ii++){
                for(int iii = 0; iii < 4 ; iii++){
                    *(encryptedData + i + ii*4 + iii) = chunk[ii][iii] ^ *(expandedKey + 16 + r*16 + ii*4 + iii);
                }
            }
        }
    }
    return encryptedData;
}

uint8_t* AES256::encrypt(uint8_t givenKey[32]){
    this->key = givenKey;
    return encrypt();
}

uint8_t* AES256::decrypt(){
    expandKey();
    uint8_t chunk[4][4];

    // and we use the tmpDataArray once again
    
    uint8_t* tmpDataArray = new uint8_t[this->encDataLength];

    for(int i = 0 ; i < this->encDataLength ; i++){
        *(tmpDataArray + i) = *(encryptedData + i);
    }

    for(int r = 1 ; r <= ROUNDCOUNT; r++){
        for(int i = 0; i < this->encDataLength; i+=16){

            for(int ii = 0 ; ii < 4 ; ii++){
                for(int iii = 0 ; iii < 4 ; iii++){
                    chunk[ii][iii] = *(tmpDataArray + i + ii*4 + iii) ^ *(expandedKey + 16 + (ROUNDCOUNT + 1 - r)*16 + ii*4 + iii);
                }
            }

            if(r != 1) invMixColumns(chunk);
            invShiftRows(chunk);

            for(auto &c : chunk){
                invSubWord(c);
            }


            for(int ii = 0; ii < 4 ; ii++){
                for(int iii = 0; iii < 4 ; iii++){
                    *(tmpDataArray + i + ii*4 + iii) = chunk[ii][iii];
                }
            }
            // there the reverse of the first step from encryption
            if(r == ROUNDCOUNT){
                for(int ii = i; ii < i+16 ; ii++){
                    *(tmpDataArray + ii) = *(tmpDataArray + ii) ^ *(key + ii%16);
                }
            }
        }
    }
    
    // remove and padding
    if(this->decDataLength == -1){
        uint8_t paddingVal = *(tmpDataArray + this->encDataLength - 1);
        this->decDataLength = this->encDataLength - paddingVal;
    }

    if(decDataLength <= 0 || decDataLength > encDataLength)
    {
        delete[] tmpDataArray;
        decDataLength = 0;
        return decryptedData = nullptr;
    }
    decryptedData = new uint8_t[decDataLength + 1];
    decryptedData[decDataLength] = '\0';

    for(int i = 0 ; i < this->decDataLength; i++){

        *(decryptedData + i) = *(tmpDataArray + i);
    }
    
    // removePadding();
    delete [] tmpDataArray;
    return decryptedData;
}

uint8_t* AES256::decrypt(uint8_t givenKey[32]){
    this->key = givenKey;
    return decrypt();
}




AES256CBC::AES256CBC(long dataLength, uint8_t* key = nullptr, uint8_t* iv = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr) : AES256(dataLength, key, encryptedData, decryptedData){
    this->iv = iv;
}

uint8_t* AES256CBC::generateIv(){
    srand(time(0));
    if(!iv) iv = new uint8_t[128/8];
    for(int i = 0 ; i < 16; i++){
        *(this->iv + i) = rand() % 256;
    }
    return this->iv;
}

uint8_t* AES256CBC::encrypt(){
    expandKey();
    uint8_t chunk[4][4];

    // padding and salt 
    if(this->encDataLength == -1){
       this->encDataLength = this->decDataLength + 16 + ((16 - this->decDataLength % 16) == 0 ? 16 : (16 - this->decDataLength % 16));
    }

    if(!encryptedData) encryptedData = new uint8_t[encDataLength];

    for(int i = 0; i < this->decDataLength ; i++){
        *(encryptedData + 16 + i) = *(decryptedData + i);
    }

    // padding and salt
    addPadding();
    addSalt();

    // first blokc outside the loop
    for(int i = 0 ; i < 16; i++){
        *(this->encryptedData + i) = *(this->encryptedData + i) ^ *(this->iv + i);
    }

    // we do not need any xoring with the key itself anymore in first round because of iv


    for(int r = 1; r<=ROUNDCOUNT; r++){
        for(int ii = 0 ; ii < 4 ; ii++){
            for(int iii = 0 ; iii < 4 ; iii++){
                chunk[ii][iii] = *(encryptedData + ii*4 + iii);
            }
            subWord(chunk[ii]);
        }

        shiftRows(chunk);
            
        if(r != ROUNDCOUNT) mixColumns(chunk);

        for(int ii = 0; ii < 4 ; ii++){
            for(int iii = 0; iii < 4 ; iii++){
                *(encryptedData + ii*4 + iii) = chunk[ii][iii] ^ *(expandedKey + 16 + r*16 + ii*4 + iii);
            }
        }
    }

    for(int i = 16 ; i < this->encDataLength; i+=16){

        // xor phase - CBC moments

        for(int ii = 0 ; ii < 16; ii++){
            *(this->encryptedData + i + ii) = *(this->encryptedData + i + ii) ^ *(this->encryptedData - 16 + i + ii);
        }

        // standard phase

        for(int r = 1; r <= ROUNDCOUNT; r++){
            
            for(int ii = 0 ; ii < 4 ; ii++){
                for(int iii = 0 ; iii < 4 ; iii++){
                    chunk[ii][iii] = *(encryptedData + i + ii*4 + iii);
                }
                subWord(chunk[ii]);
            }

            shiftRows(chunk);
            
            if(r != ROUNDCOUNT) mixColumns(chunk);

            for(int ii = 0; ii < 4 ; ii++){
                for(int iii = 0; iii < 4 ; iii++){
                    *(encryptedData + i + ii*4 + iii) = chunk[ii][iii] ^ *(expandedKey + 16 + r*16 + ii*4 + iii);
                }
            }
        }
    }

    return this->encryptedData;
}

uint8_t* AES256CBC::encrypt(uint8_t givenKey[32], uint8_t iv[16]){
    this->iv = iv;
    this->key = givenKey;
    return encrypt();
}

uint8_t* AES256CBC::decrypt(){
    expandKey();
    uint8_t chunk[4][4];

    uint8_t* tmpDataArray = new uint8_t[this->encDataLength];

    for(int i = 0 ; i < this->encDataLength ; i++){
        *(tmpDataArray + i) = *(encryptedData + i);
    }

    // all the dataBlocks excluding the first one
    // we will do i > 0 because of redundancy
    for(int i = this->encDataLength; i > 0; i-=16){

        // normal phase

        // NOT REPAIRED - DO IN THE MORNING 
        for(int r = 1 ;r <= ROUNDCOUNT; r++){

            for(int ii = 0 ; ii < 4 ; ii++){
                for(int iii = 0 ; iii < 4 ; iii++){
                    chunk[ii][iii] = *(tmpDataArray + i - 16 + ii*4 + iii) ^ *(expandedKey + 16 + (ROUNDCOUNT + 1 - r)*16 + ii*4 + iii);
                }
            }


            if(r != 1) invMixColumns(chunk);
            invShiftRows(chunk);

            for(auto &c : chunk){
                invSubWord(c);
            }

            for(int ii = 0; ii < 4 ; ii++){
                for(int iii = 0; iii < 4 ; iii++){
                    *(tmpDataArray - 16 + i + ii*4 + iii) = chunk[ii][iii];
                }
            }
        }

        // xor phase
        if(i > 16){
            for(int ii = 0 ; ii < 16; ii++){
                *(tmpDataArray + i - ii - 1) = *(tmpDataArray + i - ii - 1) ^ *(tmpDataArray - 16 + i - ii - 1);
            }
        }
    }

    // xor with iv
    for(int i = 0 ; i < 16; i++){
        *(tmpDataArray + i) = *(tmpDataArray + i) ^ *(this->iv + i);
    }
    
    // remove salt and padding
    if(this->decDataLength == -1){
        uint8_t paddingVal = *(tmpDataArray + this->encDataLength - 1);
        this->decDataLength = this->encDataLength - paddingVal - 16;
    }

    if(decDataLength <= 0 || decDataLength > encDataLength)
    {
        delete[] tmpDataArray;
        decDataLength = 0;
        return decryptedData = nullptr;
    }
    decryptedData = new uint8_t[decDataLength + 1];
    decryptedData[decDataLength] = '\0';

    // for(int i = 16 ; i < this->decDataLength ; i++){
    //     *(this->decryptedData + i - 16) = *(tmpDataArray + i);
    // }

    for(int i = 0 ; i < this->decDataLength ; i++){
        *(this->decryptedData + i) = *(tmpDataArray + i + 16);
    }

    delete [] tmpDataArray;

    return this->decryptedData;
}

uint8_t* AES256CBC::decrypt(uint8_t givenKey[32], uint8_t iv[16]){
    this->iv = iv;
    this->key = givenKey;
    return decrypt();
}
