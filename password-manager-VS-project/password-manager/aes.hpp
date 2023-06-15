//
// Created by spacesheep on 5/17/23.
//
#pragma once
#ifndef PASSM_AES_HPP
#define PASSM_AES_HPP

#include <cstdint>

class AES{
protected:
// public:
    uint8_t * key;
    uint8_t * salt;
    uint8_t * encryptedData;
    uint8_t * decryptedData;

    // after all I need that data length info
    // for ECB it is with included padding
    // becase imagine the situation when we will try do decrypt message twice in a row - the old dataLength would be shrinked twice instead of once and the encryption afterwards would fail
    long encDataLength;
    long decDataLength;

    static const uint8_t SBOX[16][16];
    static const uint8_t INVSBOX[16][16];
    static const uint8_t RCON[32];

    void rotWord(uint8_t (&word)[4]);
    void subWord(uint8_t (&word)[4]);
    void invSubWord(uint8_t (&word)[4]);
    void shiftRows(uint8_t (&chunk)[4][4]);
    void invShiftRows(uint8_t (&chunk)[4][4]);

    static uint8_t mixColumnsMultiplicator(uint8_t bt, uint8_t mult);

    void mixColumns(uint8_t (&chunk)[4][4]);
    void invMixColumns(uint8_t (&chunk)[4][4]);

    virtual void expandKey() = 0;
    // void generateSalt();
    // ecb mode does not use salt so we add only padding there
    // those go for cbc mode
    void addSalt();
    void removeSalt();
    void addPadding();
    // void removePadding();

public:

    //check Safe::Safe(AESType) to see why
    virtual uint8_t* generateKey() = 0;
    virtual uint8_t* generateIv() {return nullptr;}

    virtual uint8_t* encrypt() = 0;
    virtual uint8_t* encrypt(uint8_t givenKey[16]) = 0;
    virtual uint8_t* decrypt() = 0;
    virtual uint8_t* decrypt(uint8_t givenKey[16]) = 0;

    uint8_t* encrypt(uint8_t* givenData, long& length);
    uint8_t* decrypt(uint8_t* givenData, long& length);
};

class AES128: public AES{
protected:
    static const int ROUNDCOUNT = 10;
    static const int KEYLENGTH = 16;

protected:
// public:
    uint8_t expandedKey[176];
    void expandKey();

public:
// dataLength added to constructor in each AES class
    // we need a mechanism for assigning only one amongst ecrypted or decrypted data and one of the length at a time
    // AES128(long dataLength, uint8_t* key, uint8_t* encryptedData, uint8_t* decryptedData);

    AES128(long dataLength, uint8_t* key, uint8_t* encryptedData, uint8_t* decryptedData);
    uint8_t* generateKey();
    uint8_t* encrypt();
    uint8_t* encrypt(uint8_t givenKey[16]);
    uint8_t* decrypt();
    uint8_t* decrypt(uint8_t givenKey[16]);
};

class AES192: public AES{
// private:
protected:
    static const int ROUNDCOUNT = 12;
    static const int KEYLENGTH = 24;

protected:
// public:
    // uint8_t expandedKey[208];
    uint8_t expandedKey[216];
    void expandKey();

public:
    AES192(long dataLength, uint8_t* key, uint8_t* encryptedData, uint8_t* decryptedData);
    uint8_t* generateKey();
    uint8_t* encrypt();
    uint8_t* encrypt(uint8_t givenKey[24]);
    uint8_t* decrypt();
    uint8_t* decrypt(uint8_t givenKey[24]);

};

// more or less how it should be implemented
class AES256: public AES{
// private:
protected:
    // static const int ROUNDCOUNT = 14;
    static const int ROUNDCOUNT = 14;
    static const int KEYLENGTH = 32;

protected:
// public:
    // burh 16 * 14 + 32  = 256 no 240
    // uint8_t expandedKey[240];
    uint8_t expandedKey[256];
    void expandKey();

public:
    AES256(long dataLength, uint8_t* key, uint8_t* encryptedData, uint8_t* decryptedData);
    uint8_t* generateKey();
    uint8_t* encrypt();
    uint8_t* encrypt(uint8_t givenKey[32]);
    uint8_t* decrypt();
    uint8_t* decrypt(uint8_t givenKey[32]);

};

class AES128CBC: public AES128{
private:
    uint8_t * iv;

public:
    AES128CBC(long dataLength, uint8_t* key, uint8_t* iv, uint8_t* encryptedData, uint8_t* decryptedData);
    // let's use generateKey from the above class 
    // uint8_t* generateKey();
    // we need generate iv
    uint8_t* generateIv();
    uint8_t* encrypt();
    uint8_t* encrypt(uint8_t givenKey[16], uint8_t iv[16]);
    uint8_t* decrypt();
    uint8_t* decrypt(uint8_t givenKey[16], uint8_t iv[16]);
};

class AES192CBC: public AES192{
private:
    uint8_t * iv;

public:
    AES192CBC(long dataLength, uint8_t* key, uint8_t* iv, uint8_t* encryptedData, uint8_t* decryptedData);
    uint8_t* generateIv();
    uint8_t* encrypt();
    uint8_t* encrypt(uint8_t givenKey[24], uint8_t iv[16]);
    uint8_t* decrypt();
    uint8_t* decrypt(uint8_t givenKey[24], uint8_t iv[16]);
};

class AES256CBC: public AES256{
private:
    uint8_t * iv;

public:
    AES256CBC(long dataLength, uint8_t* key, uint8_t* iv, uint8_t* encryptedData, uint8_t* decryptedData);
    uint8_t* generateIv();
    uint8_t* encrypt();
    uint8_t* encrypt(uint8_t givenKey[32], uint8_t iv[16]);
    uint8_t* decrypt();
    uint8_t* decrypt(uint8_t givenKey[32], uint8_t iv[16]);
};


#endif //PASSM_AES_HPP
