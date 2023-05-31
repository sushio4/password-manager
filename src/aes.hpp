//
// Created by spacesheep on 5/17/23.
//
#pragma once
#ifndef PASSM_AES_HPP
#define PASSM_AES_HPP

#include <cstdint>

class AES{
protected:
    uint8_t * key;
    uint8_t * salt;
    uint8_t * encryptedData;
    uint8_t * decryptedData;

    // after all I need that data length info
    long dataLength;

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
    void generateSalt();
    void addPadding();
    void removePadding();

public:

    //virtual uint8_t* generateKey() = 0;
    virtual uint8_t* encrypt() = 0;
    virtual uint8_t* encrypt(uint8_t givenKey[16]) = 0;
    virtual uint8_t* decrypt() = 0;
    virtual uint8_t* decrypt(uint8_t givenKey[16]) = 0;
};

class AES128: public AES{
private:
    static const int ROUNDCOUNT = 10;
    static const int KEYLENGTH = 16;

protected:
    uint8_t expandedKey[176];
    void expandKey();

public:
// dataLength added to constructor in each AES class
    AES128(long dataLength, uint8_t* k, uint8_t* encryptedData, uint8_t* decryptedData);
    //uint8_t* generateKey();
    uint8_t* encrypt();
    uint8_t* encrypt(uint8_t givenKey[16]);
    uint8_t* decrypt();
    uint8_t* decrypt(uint8_t givenKey[16]);
};

class AES192: public AES{
private:
    static const int ROUNDCOUNT = 12;
    static const int KEYLENGTH = 24;

protected:
    uint8_t expandedKey[208];
    void expandKey();

public:
    AES192(long dataLength, uint8_t* key = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr);
    uint8_t* generateKey();
    uint8_t* encrypt();
    uint8_t* encrypt(uint8_t givenKey[24]);
    uint8_t* decrypt();
    uint8_t* decrypt(uint8_t givenKey[24]);

};

class AES256: public AES{
private:
    static const int ROUNDCOUNT = 14;
    static const int KEYLENGTH = 32;

protected:
    uint8_t expandedKey[240];
    void expandKey();

public:
    AES256(long dataLength, uint8_t* key = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr);
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
    AES128CBC(long dataLength, uint8_t* key = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr, uint8_t * iv = nullptr);
    uint8_t* generateKey();
    uint8_t* encrypt();
    uint8_t* encrypt(uint8_t givenKey[16], uint8_t iv[16]);
    uint8_t* decrypt();
    uint8_t* decrypt(uint8_t givenKey[16], uint8_t iv[16]);
};

class AES192CBC: public AES128{
private:
    uint8_t * iv;

public:
    AES192CBC(long dataLength, uint8_t* key = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr, uint8_t * iv = nullptr);
    uint8_t* generateKey();
    uint8_t* encrypt();
    uint8_t* encrypt(uint8_t givenKey[24], uint8_t iv[16]);
    uint8_t* decrypt();
    uint8_t* decrypt(uint8_t givenKey[24], uint8_t iv[16]);
};

class AES256CBC: public AES128{
private:
    uint8_t * iv;

public:
    AES256CBC(long dataLength, uint8_t* key = nullptr, uint8_t* encryptedData = nullptr, uint8_t* decryptedData = nullptr, uint8_t * iv = nullptr);
    uint8_t* generateKey();
    uint8_t* encrypt();
    uint8_t* encrypt(uint8_t givenKey[32], uint8_t iv[16]);
    uint8_t* decrypt();
    uint8_t* decrypt(uint8_t givenKey[32], uint8_t iv[16]);
};


#endif //PASSM_AES_HPP
