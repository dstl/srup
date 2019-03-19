//
// Created by AJ Poulter on 11/08/2016.
//

#include <gtest/gtest.h>

#include <SRUP.h>
#include <SRUP_Simple.h>
#include <SRUP_Init.h>
#include <SRUP_Response.h>
#include <SRUP_Activate.h>
#include <SRUP_Generic.h>
#include <SRUP_Action.h>
#include <SRUP_Data.h>
#include <SRUP_Join.h>
#include <SRUP_Human_Join.h>
#include <SRUP_Join_Cmd.h>
#include <SRUP_ID_REQ.h>
#include <SRUP_Resign.h>
#include <SRUP_Terminate.h>
#include <SRUP_Deregister.h>
#include <SRUP_Deregister_Cmd.h>
#include <SRUP_Group_Add.h>
#include <SRUP_Group_Delete.h>
#include <SRUP_Group_Destroy.h>
#include <SRUP_Observed_Join.h>
#include <SRUP_Human_Join_Resp.h>
#include <SRUP_Observed_Join_Resp.h>
#include <SRUP_Observation_Req.h>

#include <cstring>
#include <string>
#include <array>
#include <SRUP_Terminate.h>

#define TEST_DATA "QWERTYUIOPASDFGHJKLZXCVBNM1234567890!@#$%^&*()_+}{:?><vwxyz"
#define SHORT_TEST_DATA "ABC"
#define ULL_TEST_DATA 9223372036854775806
#define TOKEN "TOKEN"
#define URL "http://www.google.com"
#define DIGEST "DIGEST"
#define PVKEYFILE "private_key.pem"
#define PBKEYFILE "public_key.pem"
#define DATA_ID "My_Data_ID"
#define DATA1 "Test Data"
#define DATA2 256
#define DATA3 128.26
#define GROUP_ID "Group_0123456789ABCDEF"
#define DEV_ID 0x01234567
#define OBS_ID 0x0123456789ABCDEF
#define PBKEY "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwsGgqWU0eyw5A0l+/4ch\n69tQtxjf8GwL/QIVFdyT/fHSkxwR4Euwrhsx3vdbZjz/4yynTivy7rT3gfmbLpez\nwr4zPyDpOWjMbGY0xE96rf6g+gotAJUTZ5qmurC9F4ZEv0fSqdnI5xQM2wztBTMc\nyf6Vfumy57jhVlIDnmKZdb18YDZDoknxVmp43nsXwFaQn4X5M8LuBehKV+utHZAI\n7oAhGtRwdI3Sa4w/YUQ7nl5mxOVsupFSuuSUwMbTivHPFhjCa6rQKx/dqr39C7iG\noxj8jezfoRE2W/vn30RCrsE49J3JhAo5F2n4TBuyY85+2Jr7wxx6HIf54GEoELAV\nQwIDAQAB\n-----END PUBLIC KEY-----"
#define PVKEY "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAwsGgqWU0eyw5A0l+/4ch69tQtxjf8GwL/QIVFdyT/fHSkxwR\n4Euwrhsx3vdbZjz/4yynTivy7rT3gfmbLpezwr4zPyDpOWjMbGY0xE96rf6g+got\nAJUTZ5qmurC9F4ZEv0fSqdnI5xQM2wztBTMcyf6Vfumy57jhVlIDnmKZdb18YDZD\noknxVmp43nsXwFaQn4X5M8LuBehKV+utHZAI7oAhGtRwdI3Sa4w/YUQ7nl5mxOVs\nupFSuuSUwMbTivHPFhjCa6rQKx/dqr39C7iGoxj8jezfoRE2W/vn30RCrsE49J3J\nhAo5F2n4TBuyY85+2Jr7wxx6HIf54GEoELAVQwIDAQABAoIBAQCgCbjaOl378YUQ\nHG8Nz5+iTuBu9TPgPwlC6VkmU9IQ1YyycliGNeyDxbkffahPxUSJC4KYDCle2rqg\nxdotWV/QYbd+4q6EDIgfc4Vc4+rt29WwYnhEiDwf4Metldps4FrRzFViWaJrsOA3\niNGkejHoExoJ5kSrghM5eb+bgW6VfqcV5VOjX19kgM4A7KS4+IpJ4Lq3zOXxfaif\nRpKnf1o7IhsaocMoMbzuGhnnAxValljb9CABrWIsVt0vNd+8vk4MJVDnfg+fUOz0\n9WPbBTSpRFfkUqBuykbHZXjSsCWea9+jenleugMQk62kYmu6Jx57CO3oEhTBjDpT\nMSsalYUhAoGBAOMJSLAbE+ie7lNbirS+IAZGRdEVbO2Bvw+WQ7pL8tMzTuztflf3\nZQ3VEzXl9fRwQ9KZa494ILj1qHZeYGEhvv+L6HgRzEqCBdOEYrr0LMqyKCm7y2sm\nx1I86sx+f2xmT9YcLTOrWPlteu+/O5rVRbnOQfBOTGYVeD02SkcSJSiZAoGBANua\nH3QEnZUqv8c64YdY0Uhsf3F2w5yQuz/2Q1zhcYtvql8ssflfQUDKWT63c/tXxAcq\n1ZltPA4e5tT9EUvKMMqaejt6XDYZDkS5YiqAsLWH9STOwM+UDLvBYb7wWe/RC2lo\nk+QYKlBugqGk6zIlSSKUtW5dQ3j3lq69OGF8L8o7AoGASlX12MNk51tySRTF+5vs\nvGEx5t2PBszek+ntTwgi/4fjJaw1G/RCwB6t5Y3f1CMV8dSN5TG99RFqESehguwb\nr2xNt1KMgzDDW5gTA4eDSvK+N7vnRLQzuvd7IW2hpwpwxXgATNSjkzeHcww4JeAC\nrm2cJWRdm2cYMWKfO1nzlLECgYAgMBkIIl0OrjNp+mFwOz6BxRVxBh1p53TqzSfW\nh1zjOTzZsm1rxeCEpKQsIyum3ZhoDIk+cdppn3HqKiXM3BgGulnMOgUmEMocnKec\n3zwHf6QY/w0X3/V118SB/izQj+2CR8fVmQ0quOgA1XF76icsIGvvf1ASfQfjGO0Y\nrOE8XQKBgCxjzXKsZaVXHVmfQZE7Sw2f/GCYHPcR00o7fGJBKvlRcMifLkUZgZhj\nKxUZ2KcGrRzq5gQqkVWSy58s8uM818Q8QQninYQkbWkKYH0cDYxRfWUeFMIpUnpl\nxL76lj82D2+fvnaqKlbzpYU07jSHjozDYSwzvD6JxwbnQk4EQowG\n-----END RSA PRIVATE KEY-----"

// Before we test the SRUP message classes - we will test the crypto class

// ********************************
// CRYPTO_TESTS
// ********************************
class SRUP_CRYPTO_TESTS : public ::testing::Test
{
public:

    unsigned char* crypt;
    unsigned char* sig;

    char* test_data;
    char* short_test_data;
    uint64_t* ull_test_data;

    char* r_data;
    uint64_t* r_ull_data;

    unsigned char* uc_r_data;

    int size;
    int expected_size;

    SRUP_Crypto *crypto;
    SRUP_Crypto *crypto2;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pvkey;
    char* pbkey;


protected:

    virtual void TearDown()
    {
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pvkey;
        delete[] pbkey;
        delete[] test_data;
        delete[] short_test_data;
        delete(ull_test_data);
        delete(crypto);
    }

    virtual void SetUp()
    {
        crypto = new SRUP_Crypto;

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);
        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        test_data = new char[std::strlen(TEST_DATA)+1];
        std::strcpy(test_data, TEST_DATA);

        short_test_data = new char[std::strlen(TEST_DATA)+1];
        std::strcpy(short_test_data, SHORT_TEST_DATA);

        ull_test_data = new uint64_t;
        *ull_test_data = ULL_TEST_DATA;
    }

};

TEST_F(SRUP_CRYPTO_TESTS, EncryptF_DecryptF_Long_Data_Test)
{
    size_t input_length = std::strlen(test_data);
    size_t data_size = input_length / 16;
    if (input_length - data_size)
        data_size++;

    EXPECT_TRUE(crypto->EncryptF((unsigned char*) test_data, std::strlen(test_data), pbkeyfile));

    size = crypto->cryptLen();
    // The expected size of the crypto data is the sum of the size of three ints
    // (the input data size, the encrypted data size & the key length), plus 256 (the expected key length for
    // AES 256 encryption), the size of the initialization vector (16 bytes for AES 256), plus the length of the
    // input + the terminating 0, plus padding to make the length of the input equal to a round number of bytes...
    expected_size = sizeof(int) + 256 + 16 + sizeof(int) + sizeof(int) + (data_size * 16);
    EXPECT_EQ(size, expected_size);

    // DecryptF in place...
    r_data = (char*) crypto->DecryptF(pvkeyfile);
    EXPECT_EQ(*test_data, *r_data);

    // Now create a new Crypto object, copy the data – and decrypt.
    crypto2 = new SRUP_Crypto;
    crypt = crypto->crypt();
    crypto2->crypt(crypt, (unsigned int) size);
    r_data = (char*) crypto2->DecryptF(pvkeyfile);
    EXPECT_STREQ(test_data, r_data);

    delete(crypto2);
}

TEST_F(SRUP_CRYPTO_TESTS, Encrypt_Decrypt_Long_Data_Test)
{

    EXPECT_EQ(std::strlen(pbkey), 450);
    EXPECT_EQ(std::strlen(pvkey), 1674);

    size_t input_length = std::strlen(test_data);
    size_t data_size = input_length / 16;
    if (input_length - data_size)
        data_size++;

    EXPECT_TRUE(crypto->Encrypt((unsigned char*) test_data, std::strlen(test_data), pbkey));

    size = crypto->cryptLen();
    // The expected size of the crypto data is the sum of the size of three ints
    // (the input data size, the encrypted data size & the key length), plus 256 (the expected key length for
    // AES 256 encryption), the size of the initialization vector (16 bytes for AES 256), plus the length of the
    // input + the terminating 0, plus padding to make the length of the input equal to a round number of bytes...
    expected_size = sizeof(int) + 256 + 16 + sizeof(int) + sizeof(int) + (data_size * 16);
    EXPECT_EQ(size, expected_size);

    // Decrypt in place...
    r_data = (char*) crypto->Decrypt(pvkey);
    EXPECT_EQ(*test_data, *r_data);

    // Now create a new Crypto object, copy the data – and decrypt.
    crypto2 = new SRUP_Crypto;
    crypt = crypto->crypt();
    crypto2->crypt(crypt, (unsigned int) size);
    r_data = (char*) crypto2->Decrypt(pvkey);
    EXPECT_STREQ(test_data, r_data);

    delete(crypto2);
}

TEST_F(SRUP_CRYPTO_TESTS, EncryptF_DecryptF_Short_Data_Test)
{
    size_t input_length = std::strlen(short_test_data);
    size_t data_size = input_length / 16;
    if (input_length - data_size)
        data_size++;

    EXPECT_TRUE(crypto->EncryptF((unsigned char*) short_test_data, std::strlen(short_test_data), pbkeyfile));

    size = crypto->cryptLen();
    expected_size = sizeof(int) + 256 + 16 + sizeof(int) + sizeof(int) + (data_size * 16);
    EXPECT_EQ(size, expected_size);

    // DecryptF in place...
    r_data = (char*) crypto->DecryptF(pvkeyfile);
    EXPECT_STREQ(short_test_data, r_data);

    // Now create a new Crypto object, copy the data – and decrypt.
    crypto2 = new SRUP_Crypto;
    crypt = crypto->crypt();
    crypto2->crypt(crypt, (unsigned int) size);
    r_data = (char*) crypto2->DecryptF(pvkeyfile);
    EXPECT_STREQ(short_test_data, r_data);

    delete(crypto2);
}

TEST_F(SRUP_CRYPTO_TESTS, Encrypt_Decrypt_Short_Data_Test)
{
    size_t input_length = std::strlen(short_test_data);
    size_t data_size = input_length / 16;
    if (input_length - data_size)
        data_size++;

    EXPECT_TRUE(crypto->Encrypt((unsigned char*) short_test_data, std::strlen(short_test_data), pbkey));

    size = crypto->cryptLen();
    expected_size = sizeof(int) + 256 + 16 + sizeof(int) + sizeof(int) + (data_size * 16);
    EXPECT_EQ(size, expected_size);

    // Decrypt in place...
    r_data = (char*) crypto->Decrypt(pvkey);
    EXPECT_STREQ(short_test_data, r_data);

    // Now create a new Crypto object, copy the data – and decrypt.
    crypto2 = new SRUP_Crypto;
    crypt = crypto->crypt();
    crypto2->crypt(crypt, (unsigned int) size);
    r_data = (char*) crypto2->Decrypt(pvkey);
    EXPECT_STREQ(short_test_data, r_data);

    delete(crypto2);
}

TEST_F(SRUP_CRYPTO_TESTS, EncryptF_DecryptF_ULL_Data_Test)
{
    size_t input_length = sizeof(uint64_t);
    size_t data_size = input_length / 16;
    if (input_length - data_size)
        data_size++;

    EXPECT_TRUE(crypto->EncryptF((unsigned char*) ull_test_data, sizeof(uint64_t), pbkeyfile));

    size = crypto->cryptLen();
    expected_size = sizeof(int) + 256 + 16 + sizeof(int) + sizeof(int) + (data_size * 16);
    EXPECT_EQ(size, expected_size);

    // DecryptF in place...
    r_ull_data = (uint64_t*) crypto->DecryptF(pvkeyfile);
    EXPECT_EQ(*ull_test_data, *r_ull_data);

    // Now create a new Crypto object, copy the data – and decrypt.
    crypto2 = new SRUP_Crypto;
    crypt = crypto->crypt();
    crypto2->crypt(crypt, (unsigned int) size);
    r_ull_data = (uint64_t *) crypto2->DecryptF(pvkeyfile);
    EXPECT_EQ(*ull_test_data, *r_ull_data);

    delete(crypto2);
}

TEST_F(SRUP_CRYPTO_TESTS, Encrypt_Decrypt_ULL_Data_Test)
{
    size_t input_length = sizeof(uint64_t);
    size_t data_size = input_length / 16;
    if (input_length - data_size)
        data_size++;

    EXPECT_TRUE(crypto->Encrypt((unsigned char*) ull_test_data, sizeof(uint64_t), pbkey));

    size = crypto->cryptLen();
    expected_size = sizeof(int) + 256 + 16 + sizeof(int) + sizeof(int) + (data_size * 16);
    EXPECT_EQ(size, expected_size);

    // Decrypt in place...
    r_ull_data = (uint64_t*) crypto->Decrypt(pvkey);
    EXPECT_EQ(*ull_test_data, *r_ull_data);

    // Now create a new Crypto object, copy the data – and decrypt.
    crypto2 = new SRUP_Crypto;
    crypt = crypto->crypt();
    crypto2->crypt(crypt, (unsigned int) size);
    r_ull_data = (uint64_t *) crypto2->Decrypt(pvkey);
    EXPECT_EQ(*ull_test_data, *r_ull_data);

    delete(crypto2);
}

TEST_F(SRUP_CRYPTO_TESTS, EncryptF_DecryptF_128_bit_Data_Test)
{

    const int raw_data_size = 16;

    uint8_t* data_128 = new uint8_t[raw_data_size];
    uint8_t* r_data_128;

    data_128[0x0] = 0x00;
    data_128[0x1] = 0x11;
    data_128[0x2] = 0x22;
    data_128[0x3] = 0x33;
    data_128[0x4] = 0x44;
    data_128[0x5] = 0x55;
    data_128[0x6] = 0x66;
    data_128[0x7] = 0x77;
    data_128[0x8] = 0x88;
    data_128[0x9] = 0x99;
    data_128[0xA] = 0xAA;
    data_128[0xB] = 0xBB;
    data_128[0xC] = 0xCC;
    data_128[0xD] = 0xDD;
    data_128[0xE] = 0xEE;
    data_128[0xF] = 0xFF;

    size_t data_size = raw_data_size;

    size_t input_length = sizeof(uint8_t) * data_size;

    if (input_length - data_size)
        data_size++;

    EXPECT_TRUE(crypto->EncryptF((unsigned char*) data_128, data_size, pbkeyfile));

    size = crypto->cryptLen();
    expected_size = sizeof(int) + 256 + 16 + sizeof(int) + sizeof(int) + data_size + 16;
    EXPECT_EQ(size, expected_size);

    // DecryptF in place...
    r_data_128 = crypto->DecryptF(pvkeyfile);
    EXPECT_EQ(*data_128, *r_data_128);

    // Now create a new Crypto object, copy the data – and decrypt.
    crypto2 = new SRUP_Crypto;
    crypt = crypto->crypt();
    crypto2->crypt(crypt, (unsigned int) size);
    r_data_128 = crypto2->DecryptF(pvkeyfile);
    EXPECT_EQ(*data_128, *r_data_128);

    delete(crypto2);
    delete[] data_128;
}

TEST_F(SRUP_CRYPTO_TESTS, Encrypt_Decrypt_128_bit_Data_Test)
{

    const int raw_data_size = 16;

    uint8_t* data_128 = new uint8_t[raw_data_size];
    uint8_t* r_data_128;

    data_128[0x0] = 0x00;
    data_128[0x1] = 0x11;
    data_128[0x2] = 0x22;
    data_128[0x3] = 0x33;
    data_128[0x4] = 0x44;
    data_128[0x5] = 0x55;
    data_128[0x6] = 0x66;
    data_128[0x7] = 0x77;
    data_128[0x8] = 0x88;
    data_128[0x9] = 0x99;
    data_128[0xA] = 0xAA;
    data_128[0xB] = 0xBB;
    data_128[0xC] = 0xCC;
    data_128[0xD] = 0xDD;
    data_128[0xE] = 0xEE;
    data_128[0xF] = 0xFF;

    size_t data_size = raw_data_size;

    size_t input_length = sizeof(uint8_t) * data_size;

    if (input_length - data_size)
        data_size++;

    EXPECT_TRUE(crypto->Encrypt((unsigned char*) data_128, data_size, pbkey));

    size = crypto->cryptLen();
    expected_size = sizeof(int) + 256 + 16 + sizeof(int) + sizeof(int) + data_size + 16;
    EXPECT_EQ(size, expected_size);

    // DecryptF in place...
    r_data_128 = crypto->Decrypt(pvkey);
    EXPECT_EQ(*data_128, *r_data_128);

    // Now create a new Crypto object, copy the data – and decrypt.
    crypto2 = new SRUP_Crypto;
    crypt = crypto->crypt();
    crypto2->crypt(crypt, (unsigned int) size);
    r_data_128 = crypto2->Decrypt(pvkey);
    EXPECT_EQ(*data_128, *r_data_128);

    delete(crypto2);
    delete[] data_128;
}

TEST_F(SRUP_CRYPTO_TESTS, SignF_VerifyF_Short_Data_Test)
{
    EXPECT_TRUE(crypto->SignF((unsigned char*) short_test_data, std::strlen(short_test_data), pvkeyfile));

    uc_r_data = (unsigned char*) short_test_data;

    // VerifyF in place...
    EXPECT_TRUE(crypto->VerifyF(uc_r_data, std::strlen(short_test_data), pbkeyfile));

    // Now create a new Crypto object, copy the data – and decrypt.
    crypto2 = new SRUP_Crypto;
    sig = crypto->signature();
    size = crypto->sigLen();
    crypto2->signature(sig, size);

    // VerifyF copy...
    EXPECT_TRUE(crypto2->VerifyF(uc_r_data, std::strlen(short_test_data), pbkeyfile));

    delete(crypto2);
}

TEST_F(SRUP_CRYPTO_TESTS, Sign_Verify_Short_Data_Test)
{
    EXPECT_TRUE(crypto->Sign((unsigned char*) short_test_data, std::strlen(short_test_data), pvkey));

    uc_r_data = (unsigned char*) short_test_data;

    // Verify in place...
    EXPECT_TRUE(crypto->Verify(uc_r_data, std::strlen(short_test_data), pbkey));

    // Now create a new Crypto object, copy the data – and decrypt.
    crypto2 = new SRUP_Crypto;
    sig = crypto->signature();
    size = crypto->sigLen();
    crypto2->signature(sig, size);

    // VerifyF copy...
    EXPECT_TRUE(crypto2->Verify(uc_r_data, std::strlen(short_test_data), pbkey));

    delete(crypto2);
}

TEST_F(SRUP_CRYPTO_TESTS, SignF_VerifyF_Long_Data_Test)
{
    EXPECT_TRUE(crypto->SignF((unsigned char*) test_data, std::strlen(test_data), pvkeyfile));

    uc_r_data = (unsigned char*) test_data;

    // VerifyF in place...
    EXPECT_TRUE(crypto->VerifyF(uc_r_data, std::strlen(test_data), pbkeyfile));

    // Now create a new Crypto object, copy the data – and decrypt.
    crypto2 = new SRUP_Crypto;
    sig = crypto->signature();
    size = crypto->sigLen();
    crypto2->signature(sig, size);

    // VerifyF copy...
    EXPECT_TRUE(crypto2->VerifyF(uc_r_data, std::strlen(test_data), pbkeyfile));

    delete(crypto2);
}

TEST_F(SRUP_CRYPTO_TESTS, Sign_Verify_Long_Data_Test)
{
    EXPECT_TRUE(crypto->Sign((unsigned char*) test_data, std::strlen(test_data), pvkey));

    uc_r_data = (unsigned char*) test_data;

    // Verify in place...
    EXPECT_TRUE(crypto->Verify(uc_r_data, std::strlen(test_data), pbkey));

    // Now create a new Crypto object, copy the data – and decrypt.
    crypto2 = new SRUP_Crypto;
    sig = crypto->signature();
    size = crypto->sigLen();
    crypto2->signature(sig, size);

    // Verify copy...
    EXPECT_TRUE(crypto2->Verify(uc_r_data, std::strlen(test_data), pbkey));

    delete(crypto2);
}

// ********************************
// INIT_TESTS
// ********************************

class SRUP_INIT_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_INIT *msg_init;
    SRUP_MSG_INIT *msg_init2;

    uint8_t * token;
    char* url;
    char* digest;

    uint16_t token_length;
    uint16_t url_length;
    uint16_t digest_length;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pvkey;
    char* pbkey;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

protected:

    virtual void TearDown()
    {
        delete(msg_init);
        delete[] token;
        delete[] url;
        delete[] digest;
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete(sequence_ID);
        delete(sender_ID);
        delete[] pvkey;
        delete[] pbkey;
    }

    virtual void SetUp()
    {
        msg_init = new SRUP_MSG_INIT;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        url_length = std::strlen(URL)+1;
        url = new char[url_length];
        std::strcpy(url, URL);

        digest_length = std::strlen(DIGEST)+1;
        digest = new char[digest_length];
        std::strcpy(digest, DIGEST);

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 55ULL;
    }

};


TEST_F(SRUP_INIT_TESTS, Set_Get_Sequence_ID)
{
    msg_init->sequenceID(sequence_ID);
    const uint64_t *sid = msg_init->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);
}

TEST_F(SRUP_INIT_TESTS, Set_Get_Sender_ID)
{
    msg_init->senderID(sender_ID);
    const uint64_t *snd = msg_init->senderID();
    EXPECT_TRUE(*snd == *sender_ID);
}

TEST_F(SRUP_INIT_TESTS, Sign_and_Verify_Message_Test)
{
    msg_init->token(token, token_length);
    msg_init->url(url, url_length);
    msg_init->digest(digest, digest_length);
    msg_init->sequenceID(sequence_ID);
    msg_init->senderID(sender_ID);

    // As this is the first test to use the key files – we'll check they exist...
    // This isn't really a test of the code – but rather a test of the test setup...
    // e.g. this could fail with perfect code – if the files are missing.

    std::ifstream pvfile_check(pvkeyfile);
    EXPECT_TRUE(pvfile_check.good()) << "Private Key File is missing";
    pvfile_check.close();

    std::ifstream pbfile_check(pbkeyfile);
    EXPECT_TRUE(pbfile_check.good()) << "Public Key File is missing";
    pbfile_check.close();

    EXPECT_TRUE(msg_init->SignF(pvkeyfile));
    EXPECT_TRUE(msg_init->VerifyF(pbkeyfile));

    r_serial_data = msg_init->Serialized();
    sz = msg_init->SerializedLength();

    uint32_t expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*4); // 2-byte sizes for 4 variable-length fields (signature, token, url, digest)
    expected_size+=token_length;
    expected_size+=std::strlen(url)+1;
    expected_size+=std::strlen(digest)+1;

    EXPECT_EQ(sz, expected_size);

    msg_init2 = new SRUP_MSG_INIT;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_init2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_init2->VerifyF(pbkeyfile));

    // Change digest...
    const uint8_t false_digest_size = 6;
    char false_digest[false_digest_size] = "FALSE";
    msg_init2->digest(false_digest, false_digest_size);

    EXPECT_FALSE(msg_init2->VerifyF(pbkeyfile));

    // Now test the key string versions
    EXPECT_TRUE(msg_init->Sign(pvkey));
    EXPECT_TRUE(msg_init->Verify(pbkey));

    r_serial_data = msg_init->Serialized();
    sz = msg_init->SerializedLength();

    msg_init2 = new SRUP_MSG_INIT;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_init2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_init2->Verify(pbkey));

    // Change digest...
    msg_init2->digest(false_digest, false_digest_size);

    EXPECT_FALSE(msg_init2->Verify(pbkey));

    delete(msg_init2);
    delete(s_serial_data);
}

TEST_F(SRUP_INIT_TESTS, Init_Generic_Deserializer_Test)
{
    msg_init->token(token, token_length);
    msg_init->url(url, url_length);
    msg_init->digest(digest, digest_length);
    msg_init->sequenceID(sequence_ID);
    msg_init->senderID(sender_ID);

    EXPECT_TRUE(msg_init->SignF(pvkeyfile));
    EXPECT_TRUE(msg_init->VerifyF(pbkeyfile));

    r_serial_data = msg_init->Serialized();
    sz = msg_init->SerializedLength();

    uint32_t expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*4); // 2-byte sizes for 4 variable-length fields (signature, token, url, digest)
    expected_size+=token_length;
    expected_size+=std::strlen(url)+1;
    expected_size+=std::strlen(digest)+1;

    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    // Repeart for key string modes
    EXPECT_TRUE(msg_init->Sign(pvkey));
    EXPECT_TRUE(msg_init->Verify(pbkey));

    r_serial_data = msg_init->Serialized();
    sz = msg_init->SerializedLength();

    EXPECT_EQ(sz, expected_size);

    delete(msg_generic);
    delete(s_serial_data);
}

TEST_F(SRUP_INIT_TESTS, SignF_Blank_Message_Test)
{
    EXPECT_FALSE(msg_init->SignF(pvkeyfile));
    EXPECT_FALSE(msg_init->Sign(pvkey));
}


TEST_F(SRUP_INIT_TESTS, Serialize_Sequence_ID_F)
{
    msg_init->sequenceID(sequence_ID);
    msg_init->token(token, token_length);
    msg_init->url(url, url_length);
    msg_init->digest(digest, digest_length);
    msg_init->senderID(sender_ID);

    msg_init->SignF(pvkeyfile);

    r_serial_data = msg_init->Serialized();
    sz = msg_init->SerializedLength();

    msg_init2 = new SRUP_MSG_INIT;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    msg_init2->DeSerialize(s_serial_data);

    const uint64_t* sid2 = msg_init2->sequenceID();
    EXPECT_TRUE(*sid2 == *sequence_ID);

    delete(msg_init2);
    delete(s_serial_data);

}

TEST_F(SRUP_INIT_TESTS, Serialize_Sequence_ID)
{
msg_init->sequenceID(sequence_ID);
msg_init->token(token, token_length);
msg_init->url(url, url_length);
msg_init->digest(digest, digest_length);
msg_init->senderID(sender_ID);

msg_init->Sign(pvkey);

r_serial_data = msg_init->Serialized();
sz = msg_init->SerializedLength();

msg_init2 = new SRUP_MSG_INIT;
s_serial_data = new unsigned char[sz];
std::memcpy(s_serial_data, r_serial_data, sz);

msg_init2->DeSerialize(s_serial_data);

const uint64_t* sid2 = msg_init2->sequenceID();
EXPECT_TRUE(*sid2 == *sequence_ID);

delete(msg_init2);
delete(s_serial_data);

}

TEST_F(SRUP_INIT_TESTS, Serialize_Sender_ID)
{
    msg_init->sequenceID(sequence_ID);
    msg_init->token(token, token_length);
    msg_init->url(url, url_length);

    msg_init->digest(digest, digest_length);
    msg_init->senderID(sender_ID);

    msg_init->SignF(pvkeyfile);

    r_serial_data = msg_init->Serialized();
    sz = msg_init->SerializedLength();

    msg_init2 = new SRUP_MSG_INIT;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);
    msg_init2->DeSerialize(s_serial_data);
    const uint64_t* snd2 = msg_init2->senderID();
    EXPECT_TRUE(*snd2 == *sender_ID);

    char* recieved_token;
    recieved_token = (char*) msg_init2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    delete (msg_init2);
    delete(s_serial_data);

}

TEST_F(SRUP_INIT_TESTS, SignF_Incomplete_Message_Test)
{
    msg_init->token(token, token_length);
    EXPECT_FALSE(msg_init->SignF(pvkeyfile));

    EXPECT_FALSE(msg_init->SignF(pvkeyfile));

    msg_init->url(url, url_length);
    EXPECT_FALSE(msg_init->SignF(pvkeyfile));

    msg_init->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_init->SignF(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_Test)
{
    msg_init->token(token, token_length);
    EXPECT_FALSE(msg_init->Sign(pvkey));

    EXPECT_FALSE(msg_init->Sign(pvkey));

    msg_init->url(url, url_length);
    EXPECT_FALSE(msg_init->Sign(pvkey));

    msg_init->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_init->Sign(pvkey));
}

TEST_F(SRUP_INIT_TESTS, SignF_Incomplete_Message_Token_Only_Test)
{
    msg_init->token(token, token_length);
    EXPECT_FALSE(msg_init->SignF(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_Token_Only_Test)
{
msg_init->token(token, token_length);
EXPECT_FALSE(msg_init->Sign(pvkey));
}

TEST_F(SRUP_INIT_TESTS, SignF_Incomplete_Message_Target_Only_Test)
{
    EXPECT_FALSE(msg_init->SignF(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_Target_Only_Test)
{
EXPECT_FALSE(msg_init->Sign(pvkey));
}


TEST_F(SRUP_INIT_TESTS, SignF_Incomplete_Message_url_Only_Test)
{
    msg_init->url(url, url_length);
    EXPECT_FALSE(msg_init->SignF(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_url_Only_Test)
{
msg_init->url(url, url_length);
EXPECT_FALSE(msg_init->Sign(pvkey));
}


TEST_F(SRUP_INIT_TESTS, SignF_Incomplete_Message_Digest_Only_Test)
{
    msg_init->digest(digest, digest_length);
    EXPECT_FALSE(msg_init->SignF(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_Digest_Only_Test)
{
msg_init->digest(digest, digest_length);
EXPECT_FALSE(msg_init->Sign(pvkey));
}


TEST_F(SRUP_INIT_TESTS, SignF_Incomplete_Message_Sequence_Only_Test)
{
    msg_init->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_init->SignF(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_Sequence_Only_Test)
{
    msg_init->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_init->Sign(pvkey));
}


TEST_F(SRUP_INIT_TESTS, SignF_Incomplete_Message_Sender_Only_Test)
{
    msg_init->senderID(sender_ID);
    EXPECT_FALSE(msg_init->SignF(pvkeyfile));
}


TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_Sender_Only_Test)
{
    msg_init->senderID(sender_ID);
    EXPECT_FALSE(msg_init->Sign(pvkey));
}

TEST_F(SRUP_INIT_TESTS, SignF_Complete_Message_Test)
{
    msg_init->token(token, token_length);
    msg_init->url(url, url_length);
    msg_init->digest(digest, digest_length);
    msg_init->senderID(sender_ID);
    msg_init->sequenceID(sequence_ID);

    EXPECT_TRUE(msg_init->SignF(pvkeyfile));

    uint8_t msg_type;
    msg_type = *msg_init->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_INITIATE);
}


TEST_F(SRUP_INIT_TESTS, Sign_Complete_Message_Test)
{
    msg_init->token(token, token_length);
    msg_init->url(url, url_length);
    msg_init->digest(digest, digest_length);
    msg_init->senderID(sender_ID);
    msg_init->sequenceID(sequence_ID);

    EXPECT_TRUE(msg_init->Sign(pvkey));

    uint8_t msg_type;
    msg_type = *msg_init->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_INITIATE);
}

TEST_F(SRUP_INIT_TESTS, SignF_and_VerifyF_Long_Message_Test)
{
    // Test 65535-byte strings for fields.
    const int length = 65535;

    uint8_t long_unit8[length];
    std::memset(long_unit8, 0xFF, length);

    std::array<char, length> url_buffer;
    url_buffer.fill('x');
    std::string url_str(std::begin(url_buffer),std::end(url_buffer));
    const char* url = url_str.c_str();

    std::array<char, length> digest_buffer;
    digest_buffer.fill('B');
    std::string digest_str(std::begin(digest_buffer),std::end(digest_buffer));
    const char* digest = digest_str.c_str();

    msg_init->token(long_unit8, length);
    msg_init->url(url, url_str.length());
    msg_init->digest(digest, digest_str.length());
    msg_init->sequenceID(sequence_ID);
    msg_init->senderID(sender_ID);

    EXPECT_TRUE(msg_init->SignF(pvkeyfile));

    r_serial_data = msg_init->Serialized();
    sz = msg_init->SerializedLength();
    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequenceID
    expected_size+=8; // senderID
    expected_size+=(2*4); // 2-byte sizes for the variable-length fields (the next three - plus the signature)
    expected_size+=(3*length); // url, digest, token

    EXPECT_EQ(sz, expected_size);

    msg_init2 = new SRUP_MSG_INIT;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_init2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_init2->VerifyF(pbkeyfile));

    char* recieved_token;
    recieved_token = (char*) msg_init2->token();

    EXPECT_STREQ(recieved_token, (char*) &long_unit8);

    EXPECT_STREQ(msg_init2->url(), url);
    EXPECT_STREQ(msg_init2->digest(), digest);

    // Change digest...
    const uint8_t false_digest_size = 6;
    char false_digest[false_digest_size] = "FALSE";
    msg_init2->digest(false_digest, false_digest_size);

    EXPECT_FALSE(msg_init2->VerifyF(pbkeyfile));

    delete(msg_init2);
    delete(s_serial_data);
}

TEST_F(SRUP_INIT_TESTS, Sign_and_Verify_Long_Message_Test)
{
    // Test 65535-byte strings for fields.
    const int length = 65535;

    uint8_t long_unit8[length];
    std::memset(long_unit8, 0xFF, length);

    std::array<char, length> url_buffer;
    url_buffer.fill('x');
    std::string url_str(std::begin(url_buffer),std::end(url_buffer));
    const char* url = url_str.c_str();

    std::array<char, length> digest_buffer;
    digest_buffer.fill('B');
    std::string digest_str(std::begin(digest_buffer),std::end(digest_buffer));
    const char* digest = digest_str.c_str();

    msg_init->token(long_unit8, length);
    msg_init->url(url, url_str.length());
    msg_init->digest(digest, digest_str.length());
    msg_init->sequenceID(sequence_ID);
    msg_init->senderID(sender_ID);

    EXPECT_TRUE(msg_init->Sign(pvkey));

    r_serial_data = msg_init->Serialized();
    sz = msg_init->SerializedLength();
    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequenceID
    expected_size+=8; // senderID
    expected_size+=(2*4); // 2-byte sizes for the variable-length fields (the next three - plus the signature)
    expected_size+=(3*length); // url, digest, token

    EXPECT_EQ(sz, expected_size);

    msg_init2 = new SRUP_MSG_INIT;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_init2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_init2->Verify(pbkey));

    char* recieved_token;
    recieved_token = (char*) msg_init2->token();

    EXPECT_STREQ(recieved_token, (char*) &long_unit8);

    EXPECT_STREQ(msg_init2->url(), url);
    EXPECT_STREQ(msg_init2->digest(), digest);

    // Change digest...
    const uint8_t false_digest_size = 6;
    char false_digest[false_digest_size] = "FALSE";
    msg_init2->digest(false_digest, false_digest_size);

    EXPECT_FALSE(msg_init2->Verify(pbkey));

    delete(msg_init2);
    delete(s_serial_data);
}

// ********************************
// RESP_TESTS
// ********************************

class SRUP_RESP_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_RESPONSE *msg_resp;
    SRUP_MSG_RESPONSE *msg_resp2;

    uint8_t * token;
    uint16_t token_length;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pvkey;
    char* pbkey;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

protected:

    virtual void TearDown()
    {
        delete[] token;
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pvkey;
        delete[] pbkey;
        delete(sequence_ID);
        delete(sender_ID);
        delete(msg_resp);
    }

    virtual void SetUp()
    {
        msg_resp = new SRUP_MSG_RESPONSE;

        token_length = std::strlen(TOKEN)+1;
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 55ULL;
    }

};

TEST_F(SRUP_RESP_TESTS, SignF_Blank_Message_Test)
{
    EXPECT_FALSE(msg_resp->SignF(pvkeyfile));
}

TEST_F(SRUP_RESP_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_resp->Sign(pvkey));
}

TEST_F(SRUP_RESP_TESTS, SignF_Incomplete_Message_Test)
{
    msg_resp->token(token, token_length);
    EXPECT_FALSE(msg_resp->SignF(pvkeyfile));
}

TEST_F(SRUP_RESP_TESTS, Sign_Incomplete_Message_Test)
{
    msg_resp->token(token, token_length);
    EXPECT_FALSE(msg_resp->Sign(pvkey));
}

TEST_F(SRUP_RESP_TESTS, SignF_Complete_Message_Test)
{
    msg_resp->token(token, token_length);
    msg_resp->sequenceID(sequence_ID);
    msg_resp->senderID(sender_ID);
    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_SUCCESS);
    EXPECT_TRUE(msg_resp->SignF(pvkeyfile));

    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_FAIL_SERVER);
    EXPECT_TRUE(msg_resp->SignF(pvkeyfile));

    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_FAIL_FILE);
    EXPECT_TRUE(msg_resp->SignF(pvkeyfile));

    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_FAIL_DIGEST);
    EXPECT_TRUE(msg_resp->SignF(pvkeyfile));
}

TEST_F(SRUP_RESP_TESTS, Sign_Complete_Message_Test)
{
    msg_resp->token(token, token_length);
    msg_resp->sequenceID(sequence_ID);
    msg_resp->senderID(sender_ID);
    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_SUCCESS);
    EXPECT_TRUE(msg_resp->Sign(pvkey));

    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_FAIL_SERVER);
    EXPECT_TRUE(msg_resp->Sign(pvkey));

    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_FAIL_FILE);
    EXPECT_TRUE(msg_resp->Sign(pvkey));

    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_FAIL_DIGEST);
    EXPECT_TRUE(msg_resp->Sign(pvkey));
}

TEST_F(SRUP_RESP_TESTS, SignF_and_VerifyF_Message_Test)
{
    msg_resp->token(token, token_length);
    msg_resp->sequenceID(sequence_ID);
    msg_resp->senderID(sender_ID);
    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_SUCCESS);

    EXPECT_TRUE(msg_resp->SignF(pvkeyfile));

    uint8_t msg_type;
    msg_type = *msg_resp->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_RESPONSE);

    r_serial_data = msg_resp->Serialized();
    sz = msg_resp->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=1; // status
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_resp2 = new SRUP_MSG_RESPONSE;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_resp2->DeSerialize(s_serial_data));

    const uint64_t* sid = msg_resp2->sequenceID();
    const uint64_t* sndid = msg_resp2->senderID();

    EXPECT_TRUE(*sid == *sequence_ID);
    EXPECT_TRUE(*sndid == *sender_ID);

    EXPECT_TRUE(msg_resp2->VerifyF(pbkeyfile));

    // Alter the token...
    token[0]=token[1];

    msg_resp2->token(token, token_length);
    EXPECT_FALSE(msg_resp2->VerifyF(pbkeyfile));

    delete(msg_resp2);
    delete(s_serial_data);
}

TEST_F(SRUP_RESP_TESTS, Sign_and_Verify_Message_Test)
{
    msg_resp->token(token, token_length);
    msg_resp->sequenceID(sequence_ID);
    msg_resp->senderID(sender_ID);
    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_SUCCESS);

    EXPECT_TRUE(msg_resp->Sign(pvkey));

    uint8_t msg_type;
    msg_type = *msg_resp->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_RESPONSE);

    r_serial_data = msg_resp->Serialized();
    sz = msg_resp->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=1; // status
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_resp2 = new SRUP_MSG_RESPONSE;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_resp2->DeSerialize(s_serial_data));

    const uint64_t* sid = msg_resp2->sequenceID();
    const uint64_t* sndid = msg_resp2->senderID();

    EXPECT_TRUE(*sid == *sequence_ID);
    EXPECT_TRUE(*sndid == *sender_ID);

    EXPECT_TRUE(msg_resp2->Verify(pbkey));

    // Alter the token...
    token[0]=token[1];

    msg_resp2->token(token, token_length);
    EXPECT_FALSE(msg_resp2->VerifyF(pbkeyfile));

    delete(msg_resp2);
    delete(s_serial_data);
}

TEST_F(SRUP_RESP_TESTS, Generic_Deserializer_Test)
{
    msg_resp->token(token, token_length);
    msg_resp->sequenceID(sequence_ID);
    msg_resp->senderID(sender_ID);
    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_SUCCESS);

    EXPECT_TRUE(msg_resp->SignF(pvkeyfile));

    r_serial_data = msg_resp->Serialized();
    sz = msg_resp->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=1; // status
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    const uint64_t* sid = msg_generic->sequenceID();
    const uint64_t* sndid = msg_generic->senderID();

    EXPECT_TRUE(*sid == *sequence_ID);
    EXPECT_TRUE(*sndid == *sender_ID);

    // Now test the key string version
    EXPECT_TRUE(msg_resp->Sign(pvkey));

    r_serial_data = msg_resp->Serialized();
    sz = msg_resp->SerializedLength();
    EXPECT_EQ(sz, expected_size);

    delete(msg_generic);
    delete(s_serial_data);
}

// ********************************
// ACTIVATE_TESTS
// ********************************

class SRUP_ACTIVATE_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_ACTIVATE *msg_activate;
    SRUP_MSG_ACTIVATE *msg_activate2;

    uint8_t* token;
    uint16_t token_length;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pvkey;
    char* pbkey;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

protected:

    virtual void TearDown()
    {
        delete[] token;
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pvkey;
        delete[] pbkey;
        delete(sequence_ID);
        delete(sender_ID);
        delete(msg_activate);
    }

    virtual void SetUp()
    {
        msg_activate = new SRUP_MSG_ACTIVATE;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 555ULL;

    }

};

TEST_F(SRUP_ACTIVATE_TESTS, SignF_Blank_Message_Test)
{
    EXPECT_FALSE(msg_activate->SignF(pvkeyfile));
}

TEST_F(SRUP_ACTIVATE_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_activate->Sign(pvkey));
}


TEST_F(SRUP_ACTIVATE_TESTS, SignF_Complete_Message_Test)
{
    msg_activate->token(token, token_length);
    msg_activate->sequenceID(sequence_ID);
    msg_activate->senderID(sender_ID);
    EXPECT_TRUE(msg_activate->SignF(pvkeyfile));
}

TEST_F(SRUP_ACTIVATE_TESTS, Sign_Complete_Message_Test)
{
    msg_activate->token(token, token_length);
    msg_activate->sequenceID(sequence_ID);
    msg_activate->senderID(sender_ID);
    EXPECT_TRUE(msg_activate->Sign(pvkey));
}

TEST_F(SRUP_ACTIVATE_TESTS, SignF_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_activate->SignF(pvkeyfile));
    msg_activate->token(token, token_length);
    EXPECT_FALSE(msg_activate->SignF(pvkeyfile));
    msg_activate->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_activate->SignF(pvkeyfile));
    msg_activate->senderID(sender_ID);
    EXPECT_TRUE(msg_activate->SignF(pvkeyfile));
}

TEST_F(SRUP_ACTIVATE_TESTS, Sign_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_activate->Sign(pvkey));
    msg_activate->token(token, token_length);
    EXPECT_FALSE(msg_activate->Sign(pvkey));
    msg_activate->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_activate->Sign(pvkey));
    msg_activate->senderID(sender_ID);
    EXPECT_TRUE(msg_activate->Sign(pvkey));
}

TEST_F(SRUP_ACTIVATE_TESTS, SignF_and_VerifyF_Message_Test)
{
    msg_activate->token(token, token_length);
    msg_activate->sequenceID(sequence_ID);
    msg_activate->senderID(sender_ID);

    EXPECT_TRUE(msg_activate->SignF(pvkeyfile));

    uint8_t msg_type;
    msg_type = *msg_activate->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_ACTIVATE);

    r_serial_data = msg_activate->Serialized();
    sz = msg_activate->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_activate2 = new SRUP_MSG_ACTIVATE;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_activate2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_activate2->VerifyF(pbkeyfile));

    char* recieved_token;
    recieved_token = (char*) msg_activate2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_activate2->token(token, token_length);

    recieved_token = (char*) msg_activate2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_activate2->VerifyF(pbkeyfile));

    delete(msg_activate2);
    delete(s_serial_data);
}

TEST_F(SRUP_ACTIVATE_TESTS, Sign_and_Verify_Message_Test)
{
    msg_activate->token(token, token_length);
    msg_activate->sequenceID(sequence_ID);
    msg_activate->senderID(sender_ID);

    EXPECT_TRUE(msg_activate->Sign(pvkey));

    uint8_t msg_type;
    msg_type = *msg_activate->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_ACTIVATE);

    r_serial_data = msg_activate->Serialized();
    sz = msg_activate->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_activate2 = new SRUP_MSG_ACTIVATE;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_activate2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_activate2->Verify(pbkey));

    char* recieved_token;
    recieved_token = (char*) msg_activate2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_activate2->token(token, token_length);

    recieved_token = (char*) msg_activate2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_activate2->Verify(pbkey));

    delete(msg_activate2);
    delete(s_serial_data);
}


TEST_F(SRUP_ACTIVATE_TESTS, Generic_Deserialize_Test)
{
    msg_activate->token(token, token_length);
    msg_activate->sequenceID(sequence_ID);
    msg_activate->senderID(sender_ID);

    EXPECT_TRUE(msg_activate->SignF(pvkeyfile));

    r_serial_data = msg_activate->Serialized();
    sz = msg_activate->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    char* recieved_token;
    recieved_token = (char*) msg_generic->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    EXPECT_TRUE(msg_activate->Sign(pvkey));

    r_serial_data = msg_activate->Serialized();
    sz = msg_activate->SerializedLength();

    EXPECT_EQ(sz, expected_size);

    delete(msg_generic);
    delete(s_serial_data);
}


// ********************************
// GENERIC_TESTS
// ********************************

class SRUP_GENERIC_TESTS : public ::testing::Test
{
public:

    SRUP_MSG_GENERIC *msg_generic;
    SRUP_MSG_GENERIC *msg_generic2;

    SRUP_MSG_INIT *msg_init;
    SRUP_MSG_RESPONSE *msg_resp;
    SRUP_MSG_ACTIVATE *msg_activate;
    SRUP_MSG_ACTION *msg_action;
    SRUP_MSG_DATA *msg_data;

    uint8_t* action;

    uint8_t* data_ID;
    uint16_t data_ID_length;

    uint8_t* data;
    uint16_t data_length;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pvkey;
    char* pbkey;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

    char* url;
    char* digest;

    uint16_t url_length;
    uint16_t digest_length;

    char* token;
    uint16_t token_len;

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;

    size_t sz;

protected:

    virtual void TearDown()
    {
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pvkey;
        delete[] pbkey;

        delete(sequence_ID);
        delete(sender_ID);
        delete(token);
        delete(url);
        delete(digest);

        delete(action);
        delete(data);
        delete(data_ID);

        delete(msg_generic);
    }

    virtual void SetUp()
    {
        msg_generic = new SRUP_MSG_GENERIC;

        uint8_t msg_type;
        msg_type = *msg_generic->msgtype();
        EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_GENERIC);

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 7777ULL;

        token_len = std::strlen(TOKEN)+1;
        token = new char[token_len];
        std::strncpy(token, TOKEN, token_len);

        url_length = std::strlen(URL)+1;
        url = new char[url_length];
        std::strcpy(url, URL);

        digest_length = std::strlen(DIGEST)+1;
        digest = new char[digest_length];
        std::strcpy(digest, DIGEST);

        action = new uint8_t;
        *action=0xFF;

        data_length = std::strlen(DATA1);
        data = new uint8_t[data_length];
        std::memcpy(data, DATA1, data_length);

        data_ID_length = std::strlen(DATA_ID);
        data_ID = new uint8_t[data_ID_length];
        std::memcpy(data_ID, DATA_ID, data_ID_length);
    }

};

TEST_F(SRUP_GENERIC_TESTS, MessageTypeSenderAndSeqIDTest)
{
    const uint8_t *x = msg_generic->msgtype();
    EXPECT_TRUE(*x == SRUP::SRUP_MESSAGE_TYPE_GENERIC);

    msg_generic->token((uint8_t*) token, token_len);
    msg_generic->sequenceID(sequence_ID);
    msg_generic->senderID(sender_ID);
    r_serial_data=msg_generic->Serialized();
    sz = msg_generic->SerializedLength();

    int expected_size=0;

    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID

    expected_size+=2; // token length
    expected_size+=token_len; // token

    EXPECT_EQ(sz, expected_size);

    msg_generic2 = new SRUP_MSG_GENERIC;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic2->DeSerialize(s_serial_data));

    const uint64_t* sid = msg_generic2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);

    const uint64_t* snd = msg_generic2->sequenceID();
    EXPECT_TRUE(*snd == *sequence_ID);

    char* recieved_token;
    recieved_token = (char*) msg_generic2->token();

    EXPECT_STREQ(recieved_token, (char*) token);
    delete(msg_generic2);
    delete[] s_serial_data;
}

TEST_F(SRUP_GENERIC_TESTS, InitMessageToGeneric_F)
{
    msg_init = new SRUP_MSG_INIT;

    msg_init->token((uint8_t*) token, token_len);
    msg_init->sequenceID(sequence_ID);
    msg_init->senderID(sender_ID);
    msg_init->digest(digest, digest_length);
    msg_init->url(url, url_length);

    EXPECT_TRUE(msg_init->SignF(pvkeyfile));

    r_serial_data=msg_init->Serialized();
    sz = msg_init->SerializedLength();

    uint32_t expected_size=0;

    expected_size+=256; // SignFature
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*4); // 2-byte sizes for 4 variable-length fields (signature, token, url, digest)
    expected_size+=token_len;
    expected_size+=std::strlen(url)+1;
    expected_size+=std::strlen(digest)+1;

    EXPECT_EQ(sz, expected_size);

    msg_generic2 = new SRUP_MSG_GENERIC;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic2->DeSerialize(s_serial_data));

    const uint64_t* sid = msg_generic2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);

    const uint64_t* snd = msg_generic2->sequenceID();
    EXPECT_TRUE(*snd == *sequence_ID);

    char* recieved_token;
    recieved_token = (char*) msg_generic2->token();
    EXPECT_STREQ(recieved_token, (char*) token);

    delete(s_serial_data);
    delete(msg_generic2);
    delete(msg_init);
}

TEST_F(SRUP_GENERIC_TESTS, InitMessageToGeneric)
{
    msg_init = new SRUP_MSG_INIT;

    msg_init->token((uint8_t*) token, token_len);
    msg_init->sequenceID(sequence_ID);
    msg_init->senderID(sender_ID);
    msg_init->digest(digest, digest_length);
    msg_init->url(url, url_length);

    EXPECT_TRUE(msg_init->Sign(pvkey));

    r_serial_data=msg_init->Serialized();
    sz = msg_init->SerializedLength();

    uint32_t expected_size=0;

    expected_size+=256; // SignFature
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*4); // 2-byte sizes for 4 variable-length fields (signature, token, url, digest)
    expected_size+=token_len;
    expected_size+=std::strlen(url)+1;
    expected_size+=std::strlen(digest)+1;

    EXPECT_EQ(sz, expected_size);

    msg_generic2 = new SRUP_MSG_GENERIC;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic2->DeSerialize(s_serial_data));

    const uint64_t* sid = msg_generic2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);

    const uint64_t* snd = msg_generic2->sequenceID();
    EXPECT_TRUE(*snd == *sequence_ID);

    char* recieved_token;
    recieved_token = (char*) msg_generic2->token();
    EXPECT_STREQ(recieved_token, (char*) token);

    delete(s_serial_data);
    delete(msg_generic2);
    delete(msg_init);
}


TEST_F(SRUP_GENERIC_TESTS, RespMessageToGeneric_F)
{
    msg_resp = new SRUP_MSG_RESPONSE;

    msg_resp->token((uint8_t*) token, token_len);
    msg_resp->sequenceID(sequence_ID);
    msg_resp->senderID(sender_ID);
    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_SUCCESS);

    EXPECT_TRUE(msg_resp->SignF(pvkeyfile));

    r_serial_data=msg_resp->Serialized();
    sz = msg_resp->SerializedLength();

    uint32_t expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=1; // status
    expected_size+=token_len;

    EXPECT_EQ(sz, expected_size);

    msg_generic2 = new SRUP_MSG_GENERIC;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic2->DeSerialize(s_serial_data));

    const uint64_t*sid = msg_generic2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);

    const uint64_t*snd = msg_generic2->sequenceID();
    EXPECT_TRUE(*snd == *sequence_ID);

    char* recieved_token;
    recieved_token = (char*) msg_generic2->token();
    EXPECT_STREQ(recieved_token, (char*) token);

    delete(s_serial_data);
    delete(msg_generic2);
    delete(msg_resp);
}

TEST_F(SRUP_GENERIC_TESTS, RespMessageToGeneric)
{
    msg_resp = new SRUP_MSG_RESPONSE;

    msg_resp->token((uint8_t*) token, token_len);
    msg_resp->sequenceID(sequence_ID);
    msg_resp->senderID(sender_ID);
    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_SUCCESS);

    EXPECT_TRUE(msg_resp->Sign(pvkey));

    r_serial_data=msg_resp->Serialized();
    sz = msg_resp->SerializedLength();

    uint32_t expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=1; // status
    expected_size+=token_len;

    EXPECT_EQ(sz, expected_size);

    msg_generic2 = new SRUP_MSG_GENERIC;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic2->DeSerialize(s_serial_data));

    const uint64_t*sid = msg_generic2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);

    const uint64_t*snd = msg_generic2->sequenceID();
    EXPECT_TRUE(*snd == *sequence_ID);

    char* recieved_token;
    recieved_token = (char*) msg_generic2->token();
    EXPECT_STREQ(recieved_token, (char*) token);

    delete(s_serial_data);
    delete(msg_generic2);
    delete(msg_resp);
}

TEST_F(SRUP_GENERIC_TESTS, ActivateMessageToGeneric_F)
{
    msg_activate = new SRUP_MSG_ACTIVATE;

    msg_activate->token((uint8_t*) token, token_len);
    msg_activate->sequenceID(sequence_ID);
    msg_activate->senderID(sender_ID);

    EXPECT_TRUE(msg_activate->SignF(pvkeyfile));

    r_serial_data=msg_activate->Serialized();
    sz = msg_activate->SerializedLength();

    uint32_t expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_len;

    EXPECT_EQ(sz, expected_size);

    msg_generic2 = new SRUP_MSG_GENERIC;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic2->DeSerialize(s_serial_data));

    const uint64_t*sid = msg_generic2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);

    const uint64_t*snd = msg_generic2->sequenceID();
    EXPECT_TRUE(*snd == *sequence_ID);

    char* recieved_token;
    recieved_token = (char*) msg_generic2->token();
    EXPECT_STREQ(recieved_token, (char*) token);

    delete(s_serial_data);
    delete(msg_generic2);
    delete(msg_activate);
}

TEST_F(SRUP_GENERIC_TESTS, ActivateMessageToGeneric)
{
    msg_activate = new SRUP_MSG_ACTIVATE;

    msg_activate->token((uint8_t*) token, token_len);
    msg_activate->sequenceID(sequence_ID);
    msg_activate->senderID(sender_ID);

    EXPECT_TRUE(msg_activate->Sign(pvkey));

    r_serial_data=msg_activate->Serialized();
    sz = msg_activate->SerializedLength();

    uint32_t expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_len;

    EXPECT_EQ(sz, expected_size);

    msg_generic2 = new SRUP_MSG_GENERIC;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic2->DeSerialize(s_serial_data));

    const uint64_t*sid = msg_generic2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);

    const uint64_t*snd = msg_generic2->sequenceID();
    EXPECT_TRUE(*snd == *sequence_ID);

    char* recieved_token;
    recieved_token = (char*) msg_generic2->token();
    EXPECT_STREQ(recieved_token, (char*) token);

    delete(s_serial_data);
    delete(msg_generic2);
    delete(msg_activate);
}

TEST_F(SRUP_GENERIC_TESTS, ActionMessageToGeneric_F)
{
    msg_action = new SRUP_MSG_ACTION;

    msg_action->token((uint8_t*) token, token_len);
    msg_action->sequenceID(sequence_ID);
    msg_action->senderID(sender_ID);
    msg_action->action_ID(action);

    EXPECT_TRUE(msg_action->SignF(pvkeyfile));

    r_serial_data=msg_action->Serialized();
    sz = msg_action->SerializedLength();

    uint32_t expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=1; // action
    expected_size+=token_len;

    EXPECT_EQ(sz, expected_size);

    msg_generic2 = new SRUP_MSG_GENERIC;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic2->DeSerialize(s_serial_data));

    const uint64_t*sid = msg_generic2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);

    const uint64_t*snd = msg_generic2->sequenceID();
    EXPECT_TRUE(*snd == *sequence_ID);

    char* recieved_token;
    recieved_token = (char*) msg_generic2->token();
    EXPECT_STREQ(recieved_token, (char*) token);

    delete(s_serial_data);
    delete(msg_generic2);
    delete(msg_action);
}

TEST_F(SRUP_GENERIC_TESTS, ActionMessageToGeneric)
{
    msg_action = new SRUP_MSG_ACTION;

    msg_action->token((uint8_t*) token, token_len);
    msg_action->sequenceID(sequence_ID);
    msg_action->senderID(sender_ID);
    msg_action->action_ID(action);

    EXPECT_TRUE(msg_action->Sign(pvkey));

    r_serial_data=msg_action->Serialized();
    sz = msg_action->SerializedLength();

    uint32_t expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=1; // action
    expected_size+=token_len;

    EXPECT_EQ(sz, expected_size);

    msg_generic2 = new SRUP_MSG_GENERIC;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic2->DeSerialize(s_serial_data));

    const uint64_t*sid = msg_generic2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);

    const uint64_t*snd = msg_generic2->sequenceID();
    EXPECT_TRUE(*snd == *sequence_ID);

    char* recieved_token;
    recieved_token = (char*) msg_generic2->token();
    EXPECT_STREQ(recieved_token, (char*) token);

    delete(s_serial_data);
    delete(msg_generic2);
    delete(msg_action);
}


TEST_F(SRUP_GENERIC_TESTS, DataMessageToGeneric_F)
{
    msg_data = new SRUP_MSG_DATA;

    msg_data->token((uint8_t*) token, token_len);
    msg_data->sequenceID(sequence_ID);
    msg_data->senderID(sender_ID);
    msg_data->data_ID(data_ID, data_ID_length);
    msg_data->data(data, data_length);

    EXPECT_TRUE(msg_data->SignF(pvkeyfile));

    r_serial_data=msg_data->Serialized();
    sz = msg_data->SerializedLength();

    uint32_t expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*4); // 2-byte sizes for 4 variable-length fields
    expected_size+=token_len;
    expected_size+=data_ID_length;
    expected_size+=data_length;

    EXPECT_EQ(sz, expected_size);

    msg_generic2 = new SRUP_MSG_GENERIC;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic2->DeSerialize(s_serial_data));

    const uint64_t*sid = msg_generic2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);

    const uint64_t*snd = msg_generic2->sequenceID();
    EXPECT_TRUE(*snd == *sequence_ID);

    char* recieved_token;
    recieved_token = (char*) msg_generic2->token();
    EXPECT_STREQ(recieved_token, (char*) token);

    delete(s_serial_data);
    delete(msg_generic2);
    delete(msg_data);
}

TEST_F(SRUP_GENERIC_TESTS, DataMessageToGeneric)
{
    msg_data = new SRUP_MSG_DATA;

    msg_data->token((uint8_t*) token, token_len);
    msg_data->sequenceID(sequence_ID);
    msg_data->senderID(sender_ID);
    msg_data->data_ID(data_ID, data_ID_length);
    msg_data->data(data, data_length);

    EXPECT_TRUE(msg_data->Sign(pvkey));

    r_serial_data=msg_data->Serialized();
    sz = msg_data->SerializedLength();

    uint32_t expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*4); // 2-byte sizes for 4 variable-length fields
    expected_size+=token_len;
    expected_size+=data_ID_length;
    expected_size+=data_length;

    EXPECT_EQ(sz, expected_size);

    msg_generic2 = new SRUP_MSG_GENERIC;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic2->DeSerialize(s_serial_data));

    const uint64_t*sid = msg_generic2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);

    const uint64_t*snd = msg_generic2->sequenceID();
    EXPECT_TRUE(*snd == *sequence_ID);

    char* recieved_token;
    recieved_token = (char*) msg_generic2->token();
    EXPECT_STREQ(recieved_token, (char*) token);

    delete(s_serial_data);
    delete(msg_generic2);
    delete(msg_data);
}

TEST_F(SRUP_GENERIC_TESTS, SignF_Generic_Message_Test)
{
    // By definition we cannot sign a generic message...
    EXPECT_FALSE(msg_generic->SignF(pvkeyfile));
}

TEST_F(SRUP_GENERIC_TESTS, Sign_Generic_Message_Test)
{
    // By definition we cannot sign a generic message...
    EXPECT_FALSE(msg_generic->Sign(pvkey));
}

TEST_F(SRUP_GENERIC_TESTS, VerifyF_Generic_Message_Test)
{
    // ...and correspondingly we can't verify one either.
    EXPECT_FALSE(msg_generic->VerifyF(pbkeyfile));
}

TEST_F(SRUP_GENERIC_TESTS, Verify_Generic_Message_Test)
{
    // ...and correspondingly we can't verify one either.
    EXPECT_FALSE(msg_generic->Verify(pbkey));
}


// ********************************
// ACTION_TESTS
// ********************************

class SRUP_ACTION_TESTS : public ::testing::Test
{
public:

    SRUP_MSG_ACTION *msg_action;
    SRUP_MSG_ACTION *msg_action2;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pbkey;
    char* pvkey;

    uint8_t * token;
    uint16_t token_length;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

    uint8_t* action;
    uint8_t* action2;

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;

    size_t sz;

protected:

    virtual void TearDown()
    {
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pvkey;
        delete[] pbkey;

        delete(sequence_ID);
        delete(action);
        delete(action2);
        delete[] token;
        delete(sender_ID);
        delete(msg_action);
    }

    virtual void SetUp()
    {
        msg_action = new SRUP_MSG_ACTION;

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);


        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        action = new uint8_t;
        *action=0xFF;

        action2 = new uint8_t;
        *action2 = 0x55;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        sender_ID = new uint64_t;
        *sender_ID = 123ULL;
    }

};

TEST_F(SRUP_ACTION_TESTS, SignF_Blank_Message_Test)
{
    EXPECT_FALSE(msg_action->SignF(pvkeyfile));
}

TEST_F(SRUP_ACTION_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_action->Sign(pvkey));
}

TEST_F(SRUP_ACTION_TESTS, SignF_Incomplete_Message_Test)
{
    msg_action->token(token, token_length);
    EXPECT_FALSE(msg_action->SignF(pvkeyfile));
    msg_action->action_ID(action);
    EXPECT_FALSE(msg_action->SignF(pvkeyfile));
    msg_action->senderID(sender_ID);
    EXPECT_FALSE(msg_action->SignF(pvkeyfile));
}


TEST_F(SRUP_ACTION_TESTS, Sign_Incomplete_Message_Test)
{
    msg_action->token(token, token_length);
    EXPECT_FALSE(msg_action->Sign(pvkey));
    msg_action->action_ID(action);
    EXPECT_FALSE(msg_action->Sign(pvkey));
    msg_action->senderID(sender_ID);
    EXPECT_FALSE(msg_action->Sign(pvkey));
}

TEST_F(SRUP_ACTION_TESTS, SignF_Complete_Message_Test)
{
    msg_action->token(token, token_length);
    msg_action->sequenceID(sequence_ID);
    msg_action->action_ID(action);
    msg_action->senderID(sender_ID);
    EXPECT_TRUE(msg_action->SignF(pvkeyfile));
}

TEST_F(SRUP_ACTION_TESTS, Sign_Complete_Message_Test)
{
    msg_action->token(token, token_length);
    msg_action->sequenceID(sequence_ID);
    msg_action->action_ID(action);
    msg_action->senderID(sender_ID);
    EXPECT_TRUE(msg_action->Sign(pvkey));
}

TEST_F(SRUP_ACTION_TESTS, TestActions)
{
    msg_action->action_ID(action);
    EXPECT_TRUE(*msg_action->action_ID() == *action);
    msg_action->action_ID(action2);
    EXPECT_FALSE(*msg_action->action_ID() == *action);
}

TEST_F(SRUP_ACTION_TESTS, SignF_and_VerifyF_Message_Test)
{
    msg_action->token(token, token_length);
    msg_action->sequenceID(sequence_ID);
    msg_action->senderID(sender_ID);
    msg_action->action_ID(action);

    EXPECT_TRUE(msg_action->SignF(pvkeyfile));

    uint8_t msg_type;
    msg_type = *msg_action->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_ACTION);

    r_serial_data = msg_action->Serialized();
    sz = msg_action->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=1; // action
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_action2 = new SRUP_MSG_ACTION;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_action2->DeSerialize(s_serial_data));
    const uint64_t* sid = msg_action2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);
    const uint64_t* snd = msg_action2->senderID();
    EXPECT_TRUE(*snd == *sender_ID);

    EXPECT_TRUE(msg_action2->VerifyF(pbkeyfile));
    EXPECT_TRUE(*msg_action2->action_ID() == *action);

    // Alter the token...
    token[0]=token[1];

    msg_action2->token(token, token_length);
    EXPECT_FALSE(msg_action2->VerifyF(pbkeyfile));

    delete(msg_action2);
    delete(s_serial_data);
}

TEST_F(SRUP_ACTION_TESTS, Sign_and_Verify_Message_Test)
{
    msg_action->token(token, token_length);
    msg_action->sequenceID(sequence_ID);
    msg_action->senderID(sender_ID);
    msg_action->action_ID(action);

    EXPECT_TRUE(msg_action->Sign(pvkey));

    uint8_t msg_type;
    msg_type = *msg_action->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_ACTION);

    r_serial_data = msg_action->Serialized();
    sz = msg_action->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=1; // action
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_action2 = new SRUP_MSG_ACTION;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_action2->DeSerialize(s_serial_data));
    const uint64_t* sid = msg_action2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);
    const uint64_t* snd = msg_action2->senderID();
    EXPECT_TRUE(*snd == *sender_ID);

    EXPECT_TRUE(msg_action2->Verify(pbkey));
    EXPECT_TRUE(*msg_action2->action_ID() == *action);

    // Alter the token...
    token[0]=token[1];

    msg_action2->token(token, token_length);
    EXPECT_FALSE(msg_action2->Verify(pbkey));

    delete(msg_action2);
    delete(s_serial_data);
}

TEST_F(SRUP_ACTION_TESTS, Generic_Deserializer_Test)
{
    msg_action->token(token, token_length);
    msg_action->sequenceID(sequence_ID);
    msg_action->senderID(sender_ID);
    msg_action->action_ID(action);

    EXPECT_TRUE(msg_action->SignF(pvkeyfile));

    r_serial_data = msg_action->Serialized();
    sz = msg_action->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=1; // action
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    EXPECT_TRUE(msg_action->Sign(pvkey));

    r_serial_data = msg_action->Serialized();
    sz = msg_action->SerializedLength();
    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));
    const uint64_t* sid = msg_generic->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);
    const uint64_t* snd = msg_generic->senderID();
    EXPECT_TRUE(*snd == *sender_ID);

    delete(msg_generic);
    delete(s_serial_data);
}

// ********************************
// DATA_TESTS
// ********************************

class SRUP_DATA_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_DATA *msg_data;
    SRUP_MSG_DATA *msg_data2;

    uint8_t* token;
    uint16_t token_length;

    uint8_t* data_ID;
    uint16_t data_ID_length;

    uint8_t* data;

    uint32_t data2;
    double data3;

    uint16_t data_length;
    uint16_t data_length2 = 4;
    uint16_t data_length3 = 8;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pbkey;
    char* pvkey;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

protected:

    virtual void TearDown()
    {
        delete[] token;
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pvkey;
        delete[] pbkey;
        delete(sequence_ID);
        delete(sender_ID);
        delete[] data;
        delete[] data_ID;
        delete(msg_data);
    }

    virtual void SetUp()
    {
        msg_data = new SRUP_MSG_DATA;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 555ULL;

        data_ID_length = std::strlen(DATA_ID);
        data_ID = new uint8_t[data_ID_length];
        std::memcpy(data_ID, DATA_ID, data_ID_length);

        data_length = std::strlen(DATA1);
        data = new uint8_t[data_length];
        std::memcpy(data, DATA1, data_length);

        data2 = DATA2;
        data3 = DATA3;
    }

};

TEST_F(SRUP_DATA_TESTS, SignF_Blank_Message_Test)
{
    EXPECT_FALSE(msg_data->SignF(pvkeyfile));
}

TEST_F(SRUP_DATA_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_data->Sign(pvkey));
}

TEST_F(SRUP_DATA_TESTS, SignF_Incomplete_Message_Test)
{
    msg_data->token(token, token_length);
    EXPECT_FALSE(msg_data->SignF(pvkeyfile));
    msg_data->data_ID(data_ID, data_ID_length);
    EXPECT_FALSE(msg_data->SignF(pvkeyfile));
    msg_data->data(data, data_length);
    EXPECT_FALSE(msg_data->SignF(pvkeyfile));
    msg_data->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_data->SignF(pvkeyfile));
}


TEST_F(SRUP_DATA_TESTS, Sign_Incomplete_Message_Test)
{
    msg_data->token(token, token_length);
    EXPECT_FALSE(msg_data->Sign(pvkey));
    msg_data->data_ID(data_ID, data_ID_length);
    EXPECT_FALSE(msg_data->Sign(pvkey));
    msg_data->data(data, data_length);
    EXPECT_FALSE(msg_data->Sign(pvkey));
    msg_data->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_data->Sign(pvkey));
}

TEST_F(SRUP_DATA_TESTS, SignF_Complete_Message_Test)
{
    msg_data->token(token, token_length);
    msg_data->sequenceID(sequence_ID);
    msg_data->data_ID(data_ID, data_ID_length);
    msg_data->senderID(sender_ID);
    msg_data->data(data, data_length);
    EXPECT_TRUE(msg_data->SignF(pvkeyfile));
}

TEST_F(SRUP_DATA_TESTS, Sign_Complete_Message_Test)
{
    msg_data->token(token, token_length);
    msg_data->sequenceID(sequence_ID);
    msg_data->data_ID(data_ID, data_ID_length);
    msg_data->senderID(sender_ID);
    msg_data->data(data, data_length);
    EXPECT_TRUE(msg_data->Sign(pvkey));
}

TEST_F(SRUP_DATA_TESTS, TestDataTypes)
{
    msg_data->data(data, data_length);
    EXPECT_TRUE(*msg_data->data() == *data);
    msg_data->data(data2);
    EXPECT_FALSE(*msg_data->data() == *data);
    EXPECT_TRUE(*msg_data->data_uint32() == data2);
    msg_data->data(data3);
    EXPECT_FALSE(*msg_data->data() == *data);
    EXPECT_TRUE(*msg_data->data_double() == data3);
}

TEST_F(SRUP_DATA_TESTS, TestDataIDs)
{
    msg_data->data_ID(data_ID, data_ID_length);
    char* rec = (char*) msg_data->data_ID();
    EXPECT_EQ(*rec, *data_ID);

    const int length = 65535;
    uint8_t long_uint8[length];
    std::memset(long_uint8, 0xFF, length);
    msg_data->data_ID(long_uint8, length);
    rec = (char*) msg_data->data_ID();

    EXPECT_FALSE(std::memcmp(rec, long_uint8, length));
}

TEST_F(SRUP_DATA_TESTS, SignF_and_VerifyF_Message_Test)
{
    msg_data->token(token, token_length);
    msg_data->sequenceID(sequence_ID);
    msg_data->senderID(sender_ID);
    msg_data->data_ID(data_ID, data_ID_length);
    msg_data->data(data, data_length);

    EXPECT_TRUE(msg_data->SignF(pvkeyfile));
    EXPECT_TRUE(msg_data->VerifyF(pbkeyfile));

    r_serial_data = msg_data->Serialized();
    sz = msg_data->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*4); // 2-byte sizes for 4 variable-length fields
    expected_size+=token_length;
    expected_size+=data_ID_length;
    expected_size+=data_length;

    EXPECT_EQ(sz, expected_size);

    msg_data2 = new SRUP_MSG_DATA;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_data2->DeSerialize(s_serial_data));
    const uint64_t* sid = msg_data2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);
    const uint64_t* snd = msg_data2->senderID();
    EXPECT_TRUE(*snd == *sender_ID);

    EXPECT_TRUE(msg_data2->VerifyF(pbkeyfile));

    // Alter the token...
    token[0]=token[1];

    msg_data2->token(token, token_length);
    EXPECT_FALSE(msg_data2->VerifyF(pbkeyfile));

    delete(msg_data2);
    delete(s_serial_data);
}

TEST_F(SRUP_DATA_TESTS, Sign_and_Verify_Message_Test)
{
    msg_data->token(token, token_length);
    msg_data->sequenceID(sequence_ID);
    msg_data->senderID(sender_ID);
    msg_data->data_ID(data_ID, data_ID_length);
    msg_data->data(data, data_length);

    EXPECT_TRUE(msg_data->Sign(pvkey));
    EXPECT_TRUE(msg_data->Verify(pbkey));

    r_serial_data = msg_data->Serialized();
    sz = msg_data->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*4); // 2-byte sizes for 4 variable-length fields
    expected_size+=token_length;
    expected_size+=data_ID_length;
    expected_size+=data_length;

    EXPECT_EQ(sz, expected_size);

    msg_data2 = new SRUP_MSG_DATA;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_data2->DeSerialize(s_serial_data));
    const uint64_t* sid = msg_data2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);
    const uint64_t* snd = msg_data2->senderID();
    EXPECT_TRUE(*snd == *sender_ID);

    EXPECT_TRUE(msg_data2->Verify(pbkey));

    // Alter the token...
    token[0]=token[1];

    msg_data2->token(token, token_length);
    EXPECT_FALSE(msg_data2->Verify(pbkey));

    delete(msg_data2);
    delete(s_serial_data);
}

TEST_F(SRUP_DATA_TESTS, Generic_Deserializer_Test)
{
    msg_data->token(token, token_length);
    msg_data->sequenceID(sequence_ID);
    msg_data->senderID(sender_ID);
    msg_data->data_ID(data_ID, data_ID_length);
    msg_data->data(data, data_length);

    EXPECT_TRUE(msg_data->SignF(pvkeyfile));
    EXPECT_TRUE(msg_data->VerifyF(pbkeyfile));

    r_serial_data = msg_data->Serialized();
    sz = msg_data->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*4); // 2-byte sizes for 4 variable-length fields
    expected_size+=token_length;
    expected_size+=data_ID_length;
    expected_size+=data_length;

    EXPECT_EQ(sz, expected_size);

    EXPECT_TRUE(msg_data->Sign(pvkey));
    EXPECT_TRUE(msg_data->Verify(pbkey));

    r_serial_data = msg_data->Serialized();
    sz = msg_data->SerializedLength();

    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));
    const uint64_t* sid = msg_generic->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);
    const uint64_t* snd = msg_generic->senderID();
    EXPECT_TRUE(*snd == *sender_ID);

    delete(msg_generic);
    delete(s_serial_data);
}

TEST_F(SRUP_DATA_TESTS, Data_DataTypes_Test_Mashalling_F)
{
    msg_data->token(token, token_length);
    msg_data->sequenceID(sequence_ID);
    msg_data->senderID(sender_ID);
    msg_data->data_ID(data_ID, data_ID_length);
    msg_data->data(data, data_length);

    msg_data->SignF(pvkeyfile);

    uint8_t msg_type;
    msg_type = *msg_data->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_DATA);

    r_serial_data = msg_data->Serialized();
    sz = msg_data->SerializedLength();

    msg_data2 = new SRUP_MSG_DATA;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_data2->DeSerialize(s_serial_data));
    EXPECT_TRUE(*msg_data2->data() == *data);

    delete(s_serial_data);
    delete(msg_data2);

    msg_data->data(data2);
    msg_data->SignF(pvkeyfile);
    r_serial_data = msg_data->Serialized();
    sz = msg_data->SerializedLength();
    msg_data2 = new SRUP_MSG_DATA;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);
    EXPECT_TRUE(msg_data2->DeSerialize(s_serial_data));
    EXPECT_TRUE(*msg_data2->data_uint32() == data2);

    delete(s_serial_data);
    delete(msg_data2);

    msg_data->data(data3);
    msg_data->SignF(pvkeyfile);
    r_serial_data = msg_data->Serialized();
    sz = msg_data->SerializedLength();
    msg_data2 = new SRUP_MSG_DATA;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);
    EXPECT_TRUE(msg_data2->DeSerialize(s_serial_data));
    EXPECT_TRUE(*msg_data2->data_double() == data3);

    delete(msg_data2);
    delete(s_serial_data);
}

TEST_F(SRUP_DATA_TESTS, Data_DataTypes_Test_Mashalling)
{
    msg_data->token(token, token_length);
    msg_data->sequenceID(sequence_ID);
    msg_data->senderID(sender_ID);
    msg_data->data_ID(data_ID, data_ID_length);
    msg_data->data(data, data_length);

    msg_data->Sign(pvkey);

    uint8_t msg_type;
    msg_type = *msg_data->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_DATA);

    r_serial_data = msg_data->Serialized();
    sz = msg_data->SerializedLength();

    msg_data2 = new SRUP_MSG_DATA;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_data2->DeSerialize(s_serial_data));
    EXPECT_TRUE(*msg_data2->data() == *data);

    delete(s_serial_data);
    delete(msg_data2);

    msg_data->data(data2);
    msg_data->Sign(pvkey);
    r_serial_data = msg_data->Serialized();
    sz = msg_data->SerializedLength();
    msg_data2 = new SRUP_MSG_DATA;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);
    EXPECT_TRUE(msg_data2->DeSerialize(s_serial_data));
    EXPECT_TRUE(*msg_data2->data_uint32() == data2);

    delete(s_serial_data);
    delete(msg_data2);

    msg_data->data(data3);
    msg_data->Sign(pvkey);
    r_serial_data = msg_data->Serialized();
    sz = msg_data->SerializedLength();
    msg_data2 = new SRUP_MSG_DATA;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);
    EXPECT_TRUE(msg_data2->DeSerialize(s_serial_data));
    EXPECT_TRUE(*msg_data2->data_double() == data3);

    delete(msg_data2);
    delete(s_serial_data);
}

// ********************************
// JOIN_REQ_TESTS
// ********************************

class SRUP_JOIN_REQ_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_JOIN_REQ *msg_join;
    SRUP_MSG_JOIN_REQ *msg_join2;

    uint8_t* token;
    uint16_t token_length;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pvkey;
    char* pbkey;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

protected:

    virtual void TearDown()
    {
        delete[] token;
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pvkey;
        delete[] pbkey;
        delete(sequence_ID);
        delete(sender_ID);
        delete(msg_join);
    }

    virtual void SetUp()
    {
        msg_join = new SRUP_MSG_JOIN_REQ;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 555ULL;

    }

};

TEST_F(SRUP_JOIN_REQ_TESTS, SignF_Blank_Message_Test)
{
    EXPECT_FALSE(msg_join->SignF(pvkeyfile));
}

TEST_F(SRUP_JOIN_REQ_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_join->Sign(pvkey));
}

TEST_F(SRUP_JOIN_REQ_TESTS, SignF_Complete_Message_Test)
{
    msg_join->token(token, token_length);
    msg_join->sequenceID(sequence_ID);
    msg_join->senderID(sender_ID);
    EXPECT_TRUE(msg_join->SignF(pvkeyfile));
}

TEST_F(SRUP_JOIN_REQ_TESTS, Sign_Complete_Message_Test)
{
    msg_join->token(token, token_length);
    msg_join->sequenceID(sequence_ID);
    msg_join->senderID(sender_ID);
    EXPECT_TRUE(msg_join->Sign(pvkey));
}

TEST_F(SRUP_JOIN_REQ_TESTS, SignF_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_join->SignF(pvkeyfile));
    msg_join->token(token, token_length);
    EXPECT_FALSE(msg_join->SignF(pvkeyfile));
    msg_join->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_join->SignF(pvkeyfile));
    msg_join->senderID(sender_ID);
    EXPECT_TRUE(msg_join->SignF(pvkeyfile));
}

TEST_F(SRUP_JOIN_REQ_TESTS, Sign_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_join->Sign(pvkey));
    msg_join->token(token, token_length);
    EXPECT_FALSE(msg_join->Sign(pvkey));
    msg_join->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_join->Sign(pvkey));
    msg_join->senderID(sender_ID);
    EXPECT_TRUE(msg_join->Sign(pvkey));
}

TEST_F(SRUP_JOIN_REQ_TESTS, SignF_and_VerifyF_Message_Test)
{
    msg_join->token(token, token_length);
    msg_join->sequenceID(sequence_ID);
    msg_join->senderID(sender_ID);

    EXPECT_TRUE(msg_join->SignF(pvkeyfile));

    uint8_t msg_type;
    msg_type = *msg_join->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_JOIN_REQ);

    r_serial_data = msg_join->Serialized();
    sz = msg_join->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_join2 = new SRUP_MSG_JOIN_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_join2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_join2->VerifyF(pbkeyfile));

    char* recieved_token;
    recieved_token = (char*) msg_join2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_join2->token(token, token_length);

    recieved_token = (char*) msg_join2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_join2->VerifyF(pbkeyfile));

    delete(msg_join2);
    delete(s_serial_data);
}

TEST_F(SRUP_JOIN_REQ_TESTS, Sign_and_Verify_Message_Test)
{
    msg_join->token(token, token_length);
    msg_join->sequenceID(sequence_ID);
    msg_join->senderID(sender_ID);

    EXPECT_TRUE(msg_join->Sign(pvkey));

    uint8_t msg_type;
    msg_type = *msg_join->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_JOIN_REQ);

    r_serial_data = msg_join->Serialized();
    sz = msg_join->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_join2 = new SRUP_MSG_JOIN_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_join2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_join2->Verify(pbkey));

    char* recieved_token;
    recieved_token = (char*) msg_join2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_join2->token(token, token_length);

    recieved_token = (char*) msg_join2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_join2->Verify(pbkey));

    delete(msg_join2);
    delete(s_serial_data);
}

TEST_F(SRUP_JOIN_REQ_TESTS, Generic_Deserializer_Test)
{
    msg_join->token(token, token_length);
    msg_join->sequenceID(sequence_ID);
    msg_join->senderID(sender_ID);

    EXPECT_TRUE(msg_join->SignF(pvkeyfile));

    r_serial_data = msg_join->Serialized();
    sz = msg_join->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    EXPECT_TRUE(msg_join->Sign(pvkey));

    r_serial_data = msg_join->Serialized();
    sz = msg_join->SerializedLength();

    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    delete(msg_generic);
    delete(s_serial_data);
}

// ********************************
// JOIN_HUMAN_REQ_TESTS
// ********************************

class SRUP_HUMAN_JOIN_REQ_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_HUMAN_JOIN_REQ *msg_join;
    SRUP_MSG_HUMAN_JOIN_REQ *msg_join2;

    uint8_t* token;
    uint16_t token_length;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pvkey;
    char* pbkey;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

protected:

    virtual void TearDown()
    {
        delete[] token;
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pbkey;
        delete[] pvkey;

        delete(sequence_ID);
        delete(sender_ID);
        delete(msg_join);
    }

    virtual void SetUp()
    {
        msg_join = new SRUP_MSG_HUMAN_JOIN_REQ;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 555ULL;
    }

};

TEST_F(SRUP_HUMAN_JOIN_REQ_TESTS, SignF_Blank_Message_Test)
{
    EXPECT_FALSE(msg_join->SignF(pvkeyfile));
}

TEST_F(SRUP_HUMAN_JOIN_REQ_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_join->Sign(pvkeyfile));
}

TEST_F(SRUP_HUMAN_JOIN_REQ_TESTS, SignF_Complete_Message_Test)
{
    msg_join->token(token, token_length);
    msg_join->sequenceID(sequence_ID);
    msg_join->senderID(sender_ID);
    EXPECT_TRUE(msg_join->SignF(pvkeyfile));
}

TEST_F(SRUP_HUMAN_JOIN_REQ_TESTS, Sign_Complete_Message_Test)
{
    msg_join->token(token, token_length);
    msg_join->sequenceID(sequence_ID);
    msg_join->senderID(sender_ID);
    EXPECT_TRUE(msg_join->Sign(pvkey));
}

TEST_F(SRUP_HUMAN_JOIN_REQ_TESTS, SignF_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_join->SignF(pvkeyfile));
    msg_join->token(token, token_length);
    EXPECT_FALSE(msg_join->SignF(pvkeyfile));
    msg_join->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_join->SignF(pvkeyfile));
    msg_join->senderID(sender_ID);
    EXPECT_TRUE(msg_join->SignF(pvkeyfile));
}

TEST_F(SRUP_HUMAN_JOIN_REQ_TESTS, Sign_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_join->Sign(pvkey));
    msg_join->token(token, token_length);
    EXPECT_FALSE(msg_join->Sign(pvkey));
    msg_join->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_join->Sign(pvkey));
    msg_join->senderID(sender_ID);
    EXPECT_TRUE(msg_join->Sign(pvkey));
}

TEST_F(SRUP_HUMAN_JOIN_REQ_TESTS, SignF_and_VerifyF_Message_Test)
{
    msg_join->token(token, token_length);
    msg_join->sequenceID(sequence_ID);
    msg_join->senderID(sender_ID);

    EXPECT_TRUE(msg_join->SignF(pvkeyfile));

    uint8_t msg_type;
    msg_type = *msg_join->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_HM_JOIN_REQ);

    r_serial_data = msg_join->Serialized();
    sz = msg_join->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_join2 = new SRUP_MSG_HUMAN_JOIN_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_join2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_join2->VerifyF(pbkeyfile));

    char* recieved_token;
    recieved_token = (char*) msg_join2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_join2->token(token, token_length);

    recieved_token = (char*) msg_join2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_join2->VerifyF(pbkeyfile));

    delete(msg_join2);
    delete(s_serial_data);
}

TEST_F(SRUP_HUMAN_JOIN_REQ_TESTS, Sign_and_Verify_Message_Test)
{
    msg_join->token(token, token_length);
    msg_join->sequenceID(sequence_ID);
    msg_join->senderID(sender_ID);

    EXPECT_TRUE(msg_join->Sign(pvkey));

    uint8_t msg_type;
    msg_type = *msg_join->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_HM_JOIN_REQ);

    r_serial_data = msg_join->Serialized();
    sz = msg_join->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_join2 = new SRUP_MSG_HUMAN_JOIN_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_join2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_join2->Verify(pbkey));

    char* recieved_token;
    recieved_token = (char*) msg_join2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_join2->token(token, token_length);

    recieved_token = (char*) msg_join2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_join2->Verify(pbkey));

    delete(msg_join2);
    delete(s_serial_data);
}

TEST_F(SRUP_HUMAN_JOIN_REQ_TESTS, Generic_Deserializer_Test)
{
    msg_join->token(token, token_length);
    msg_join->sequenceID(sequence_ID);
    msg_join->senderID(sender_ID);

    EXPECT_TRUE(msg_join->SignF(pvkeyfile));

    r_serial_data = msg_join->Serialized();
    sz = msg_join->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    EXPECT_TRUE(msg_join->Sign(pvkey));

    r_serial_data = msg_join->Serialized();
    sz = msg_join->SerializedLength();
    EXPECT_EQ(sz, expected_size);


auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    delete(msg_generic);
    delete(s_serial_data);
}

// ********************************
// JOIN_CMD_TESTS
// ********************************

class SRUP_JOIN_CMD_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_JOIN_CMD *msg_join;
    SRUP_MSG_JOIN_CMD *msg_join2;

    uint8_t* token;
    uint16_t token_length;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pvkey;
    char* pbkey;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;
    uint64_t* device_ID;

protected:

    virtual void TearDown()
    {
        delete[] token;
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pvkey;
        delete[] pbkey;
        delete(sequence_ID);
        delete(sender_ID);
        delete(device_ID);
        delete(msg_join);
    }

    virtual void SetUp()
    {
        msg_join = new SRUP_MSG_JOIN_CMD;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 555ULL;

        device_ID = new uint64_t;
        *device_ID = DEV_ID;

    }
};

TEST_F(SRUP_JOIN_CMD_TESTS, SignF_Blank_Message_Test)
{
    EXPECT_FALSE(msg_join->SignF(pvkeyfile));
}


TEST_F(SRUP_JOIN_CMD_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_join->Sign(pvkey));
}

TEST_F(SRUP_JOIN_CMD_TESTS, SignF_Complete_Message_Test)
{
    msg_join->token(token, token_length);
    msg_join->sequenceID(sequence_ID);
    msg_join->senderID(sender_ID);
    msg_join->device_ID(device_ID);
    EXPECT_TRUE(msg_join->SignF(pvkeyfile));
}

TEST_F(SRUP_JOIN_CMD_TESTS, Sign_Complete_Message_Test)
{
    msg_join->token(token, token_length);
    msg_join->sequenceID(sequence_ID);
    msg_join->senderID(sender_ID);
    msg_join->device_ID(device_ID);
    EXPECT_TRUE(msg_join->Sign(pvkey));
}

TEST_F(SRUP_JOIN_CMD_TESTS, SignF_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_join->SignF(pvkeyfile));
    msg_join->token(token, token_length);
    EXPECT_FALSE(msg_join->SignF(pvkeyfile));
    msg_join->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_join->SignF(pvkeyfile));
    msg_join->senderID(sender_ID);
    EXPECT_FALSE(msg_join->SignF(pvkeyfile));
    msg_join->device_ID(device_ID);
    EXPECT_TRUE(msg_join->SignF(pvkeyfile));
}

TEST_F(SRUP_JOIN_CMD_TESTS, Sign_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_join->Sign(pvkey));
    msg_join->token(token, token_length);
    EXPECT_FALSE(msg_join->Sign(pvkey));
    msg_join->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_join->Sign(pvkey));
    msg_join->senderID(sender_ID);
    EXPECT_FALSE(msg_join->Sign(pvkey));
    msg_join->device_ID(device_ID);
    EXPECT_TRUE(msg_join->Sign(pvkey));
}

TEST_F(SRUP_JOIN_CMD_TESTS, SignF_and_VerifyF_Message_Test)
{
    msg_join->token(token, token_length);
    msg_join->sequenceID(sequence_ID);
    msg_join->senderID(sender_ID);
    msg_join->device_ID(device_ID);

    EXPECT_TRUE(msg_join->SignF(pvkeyfile));

    uint8_t msg_type;
    msg_type = *msg_join->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_JOIN_CMD);

    r_serial_data = msg_join->Serialized();
    sz = msg_join->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=8; // device_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_join2 = new SRUP_MSG_JOIN_CMD;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_join2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_join2->VerifyF(pbkeyfile));

    char* recieved_token;
    recieved_token = (char*) msg_join2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_join2->token(token, token_length);

    recieved_token = (char*) msg_join2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_join2->VerifyF(pbkeyfile));

    delete(msg_join2);
    delete(s_serial_data);
}

TEST_F(SRUP_JOIN_CMD_TESTS, Sign_and_Verify_Message_Test)
{
    msg_join->token(token, token_length);
    msg_join->sequenceID(sequence_ID);
    msg_join->senderID(sender_ID);
    msg_join->device_ID(device_ID);

    EXPECT_TRUE(msg_join->Sign(pvkey));

    uint8_t msg_type;
    msg_type = *msg_join->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_JOIN_CMD);

    r_serial_data = msg_join->Serialized();
    sz = msg_join->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=8; // device_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_join2 = new SRUP_MSG_JOIN_CMD;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_join2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_join2->Verify(pbkey));

    char* recieved_token;
    recieved_token = (char*) msg_join2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_join2->token(token, token_length);

    recieved_token = (char*) msg_join2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_join2->VerifyF(pbkeyfile));

    delete(msg_join2);
    delete(s_serial_data);
    }

TEST_F(SRUP_JOIN_CMD_TESTS, Generic_deserializer_Test)
{
    msg_join->token(token, token_length);
    msg_join->sequenceID(sequence_ID);
    msg_join->senderID(sender_ID);
    msg_join->device_ID(device_ID);

    EXPECT_TRUE(msg_join->SignF(pvkeyfile));

    r_serial_data = msg_join->Serialized();
    sz = msg_join->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=8; // device_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    EXPECT_TRUE(msg_join->SignF(pvkeyfile));
    r_serial_data = msg_join->Serialized();
    sz = msg_join->SerializedLength();
    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    delete(msg_generic);
    delete(s_serial_data);
}

TEST_F(SRUP_JOIN_CMD_TESTS, Serialize_Device_ID_F)
{
    msg_join->sequenceID(sequence_ID);
    msg_join->token(token, token_length);
    msg_join->senderID(sender_ID);
    msg_join->device_ID(device_ID);

    msg_join->SignF(pvkeyfile);

    r_serial_data = msg_join->Serialized();
    sz = msg_join->SerializedLength();

    msg_join2 = new SRUP_MSG_JOIN_CMD;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);
    msg_join2->DeSerialize(s_serial_data);
    const uint64_t* snd2 = msg_join2->senderID();
    EXPECT_TRUE(*snd2 == *sender_ID);

    const uint64_t* dev2 = msg_join2->device_ID();
    EXPECT_TRUE(*dev2 == *device_ID);

    delete (msg_join2);
    delete(s_serial_data);

}

TEST_F(SRUP_JOIN_CMD_TESTS, Serialize_Device_ID)
{
    msg_join->sequenceID(sequence_ID);
    msg_join->token(token, token_length);
    msg_join->senderID(sender_ID);
    msg_join->device_ID(device_ID);

    msg_join->Sign(pvkey);

    r_serial_data = msg_join->Serialized();
    sz = msg_join->SerializedLength();

    msg_join2 = new SRUP_MSG_JOIN_CMD;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);
    msg_join2->DeSerialize(s_serial_data);
    const uint64_t* snd2 = msg_join2->senderID();
    EXPECT_TRUE(*snd2 == *sender_ID);

    const uint64_t* dev2 = msg_join2->device_ID();
    EXPECT_TRUE(*dev2 == *device_ID);

    delete (msg_join2);
    delete(s_serial_data);
}

// ********************************
// ID_REQ_TESTS
// ********************************

class SRUP_ID_REQ_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_ID_REQ *msg_id_req;
    SRUP_MSG_ID_REQ *msg_id_req2;

    uint8_t* token;
    uint16_t token_length;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pvkey;
    char* pbkey;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

protected:

    virtual void TearDown()
    {
        delete[] token;
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pbkey;
        delete[] pvkey;

        delete(sequence_ID);
        delete(sender_ID);
        delete(msg_id_req);
    }

    virtual void SetUp()
    {
        msg_id_req = new SRUP_MSG_ID_REQ;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 555ULL;
    }

};

TEST_F(SRUP_ID_REQ_TESTS, SignF_Blank_Message_Test)
{
    EXPECT_FALSE(msg_id_req->SignF(pvkeyfile));
}

TEST_F(SRUP_ID_REQ_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_id_req->Sign(pvkey));
}

TEST_F(SRUP_ID_REQ_TESTS, SignF_Complete_Message_Test)
{
    msg_id_req->token(token, token_length);
    msg_id_req->sequenceID(sequence_ID);
    msg_id_req->senderID(sender_ID);
    EXPECT_TRUE(msg_id_req->SignF(pvkeyfile));
}

TEST_F(SRUP_ID_REQ_TESTS, Sign_Complete_Message_Test)
{
    msg_id_req->token(token, token_length);
    msg_id_req->sequenceID(sequence_ID);
    msg_id_req->senderID(sender_ID);
    EXPECT_TRUE(msg_id_req->Sign(pvkey));
}

TEST_F(SRUP_ID_REQ_TESTS, SignF_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_id_req->SignF(pvkeyfile));
    msg_id_req->token(token, token_length);
    EXPECT_FALSE(msg_id_req->SignF(pvkeyfile));
    msg_id_req->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_id_req->SignF(pvkeyfile));
    msg_id_req->senderID(sender_ID);
    EXPECT_TRUE(msg_id_req->SignF(pvkeyfile));
}

TEST_F(SRUP_ID_REQ_TESTS, Sign_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_id_req->Sign(pvkey));
    msg_id_req->token(token, token_length);
    EXPECT_FALSE(msg_id_req->Sign(pvkey));
    msg_id_req->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_id_req->SignF(pvkey));
    msg_id_req->senderID(sender_ID);
    EXPECT_TRUE(msg_id_req->Sign(pvkey));
}

TEST_F(SRUP_ID_REQ_TESTS, SignF_and_VerifyF_Message_Test)
{
    msg_id_req->token(token, token_length);
    msg_id_req->sequenceID(sequence_ID);
    msg_id_req->senderID(sender_ID);

    EXPECT_TRUE(msg_id_req->SignF(pvkeyfile));

    uint8_t msg_type;
    msg_type = *msg_id_req->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_ID_REQUEST);

    r_serial_data = msg_id_req->Serialized();
    sz = msg_id_req->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_id_req2 = new SRUP_MSG_ID_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_id_req2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_id_req2->VerifyF(pbkeyfile));

    char* recieved_token;
    recieved_token = (char*) msg_id_req2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_id_req2->token(token, token_length);

    recieved_token = (char*) msg_id_req2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_id_req2->VerifyF(pbkeyfile));

    delete(msg_id_req2);
    delete(s_serial_data);
}

TEST_F(SRUP_ID_REQ_TESTS, Sign_and_Verify_Message_Test)
{
    msg_id_req->token(token, token_length);
    msg_id_req->sequenceID(sequence_ID);
    msg_id_req->senderID(sender_ID);

    EXPECT_TRUE(msg_id_req->Sign(pvkey));

    uint8_t msg_type;
    msg_type = *msg_id_req->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_ID_REQUEST);

    r_serial_data = msg_id_req->Serialized();
    sz = msg_id_req->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_id_req2 = new SRUP_MSG_ID_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_id_req2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_id_req2->Verify(pbkey));

    char* recieved_token;
    recieved_token = (char*) msg_id_req2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_id_req2->token(token, token_length);

    recieved_token = (char*) msg_id_req2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_id_req2->Verify(pbkey));

    delete(msg_id_req2);
    delete(s_serial_data);
}

TEST_F(SRUP_ID_REQ_TESTS, Generic_Deserialize_Test)
{
    msg_id_req->token(token, token_length);
    msg_id_req->sequenceID(sequence_ID);
    msg_id_req->senderID(sender_ID);

    EXPECT_TRUE(msg_id_req->Sign(pvkey));

    uint8_t msg_type;
    msg_type = *msg_id_req->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_ID_REQUEST);

    r_serial_data = msg_id_req->Serialized();
    sz = msg_id_req->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    EXPECT_TRUE(msg_id_req->SignF(pvkeyfile));

    msg_type = *msg_id_req->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_ID_REQUEST);

    r_serial_data = msg_id_req->Serialized();
    sz = msg_id_req->SerializedLength();

    EXPECT_EQ(sz, expected_size);

    SRUP_MSG_GENERIC* msg_generic;
    msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    msg_type = *msg_generic->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_ID_REQUEST);

    delete(msg_generic);
    delete(s_serial_data);
}

// ********************************
// RESIGN_TESTS
// ********************************

class SRUP_RESIGN_REQ_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_RESIGN_REQ *msg_res_req;
    SRUP_MSG_RESIGN_REQ *msg_res_req2;

    uint8_t* token;
    uint16_t token_length;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pbkey;
    char* pvkey;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

protected:

    virtual void TearDown()
    {
        delete[] token;
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pvkey;
        delete[] pbkey;

        delete(sequence_ID);
        delete(sender_ID);
        delete(msg_res_req);
    }

    virtual void SetUp()
    {
        msg_res_req = new SRUP_MSG_RESIGN_REQ;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 555ULL;
    }

};

TEST_F(SRUP_RESIGN_REQ_TESTS, SignF_Blank_Message_Test)
{
    EXPECT_FALSE(msg_res_req->SignF(pvkeyfile));
}

TEST_F(SRUP_RESIGN_REQ_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_res_req->Sign(pvkey));
}

TEST_F(SRUP_RESIGN_REQ_TESTS, SignF_Complete_Message_Test)
{
    msg_res_req->token(token, token_length);
    msg_res_req->sequenceID(sequence_ID);
    msg_res_req->senderID(sender_ID);
    EXPECT_TRUE(msg_res_req->SignF(pvkeyfile));
}

TEST_F(SRUP_RESIGN_REQ_TESTS, Sign_Complete_Message_Test)
{
    msg_res_req->token(token, token_length);
    msg_res_req->sequenceID(sequence_ID);
    msg_res_req->senderID(sender_ID);
    EXPECT_TRUE(msg_res_req->Sign(pvkey));
}

TEST_F(SRUP_RESIGN_REQ_TESTS, SignF_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_res_req->SignF(pvkeyfile));
    msg_res_req->token(token, token_length);
    EXPECT_FALSE(msg_res_req->SignF(pvkeyfile));
    msg_res_req->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_res_req->SignF(pvkeyfile));
    msg_res_req->senderID(sender_ID);
    EXPECT_TRUE(msg_res_req->SignF(pvkeyfile));
}

TEST_F(SRUP_RESIGN_REQ_TESTS, Sign_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_res_req->Sign(pvkey));
    msg_res_req->token(token, token_length);
    EXPECT_FALSE(msg_res_req->Sign(pvkey));
    msg_res_req->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_res_req->Sign(pvkey));
    msg_res_req->senderID(sender_ID);
    EXPECT_TRUE(msg_res_req->Sign(pvkey));
}

TEST_F(SRUP_RESIGN_REQ_TESTS, SignF_and_VerifyF_Message_Test)
{
    msg_res_req->token(token, token_length);
    msg_res_req->sequenceID(sequence_ID);
    msg_res_req->senderID(sender_ID);

    EXPECT_TRUE(msg_res_req->SignF(pvkeyfile));

    uint8_t msg_type;
    msg_type = *msg_res_req->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_RESIGN_REQUEST);

    r_serial_data = msg_res_req->Serialized();
    sz = msg_res_req->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_res_req2 = new SRUP_MSG_RESIGN_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_res_req2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_res_req2->VerifyF(pbkeyfile));

    char* recieved_token;
    recieved_token = (char*) msg_res_req2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_res_req2->token(token, token_length);

    recieved_token = (char*) msg_res_req2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_res_req2->VerifyF(pbkeyfile));

    delete(msg_res_req2);
    delete(s_serial_data);
}

TEST_F(SRUP_RESIGN_REQ_TESTS, Sign_and_Verify_Message_Test)
{
    msg_res_req->token(token, token_length);
    msg_res_req->sequenceID(sequence_ID);
    msg_res_req->senderID(sender_ID);

    EXPECT_TRUE(msg_res_req->Sign(pvkey));

    uint8_t msg_type;
    msg_type = *msg_res_req->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_RESIGN_REQUEST);

    r_serial_data = msg_res_req->Serialized();
    sz = msg_res_req->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_res_req2 = new SRUP_MSG_RESIGN_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_res_req2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_res_req2->Verify(pbkey));

    char* recieved_token;
    recieved_token = (char*) msg_res_req2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_res_req2->token(token, token_length);

    recieved_token = (char*) msg_res_req2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_res_req2->Verify(pbkey));

    delete(msg_res_req2);
    delete(s_serial_data);
}

TEST_F(SRUP_RESIGN_REQ_TESTS, Generic_Deserialize_Test)
{
    msg_res_req->token(token, token_length);
    msg_res_req->sequenceID(sequence_ID);
    msg_res_req->senderID(sender_ID);

    EXPECT_TRUE(msg_res_req->SignF(pvkeyfile));

    r_serial_data = msg_res_req->Serialized();
    sz = msg_res_req->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    EXPECT_TRUE(msg_res_req->Sign(pvkey));

    r_serial_data = msg_res_req->Serialized();
    sz = msg_res_req->SerializedLength();
    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    delete(msg_generic);
    delete(s_serial_data);
}


// ********************************
// TERMINATE_TESTS
// ********************************

class SRUP_TERMINATE_REQ_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_TERMINATE_CMD *msg_term;
    SRUP_MSG_TERMINATE_CMD *msg_term2;

    uint8_t* token;
    uint16_t token_length;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pbkey;
    char* pvkey;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

protected:

    virtual void TearDown()
    {
        delete[] token;
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pvkey;
        delete[] pbkey;

        delete(sequence_ID);
        delete(sender_ID);
        delete(msg_term);
    }

    virtual void SetUp()
    {
        msg_term = new SRUP_MSG_TERMINATE_CMD;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 555ULL;
    }
};

TEST_F(SRUP_TERMINATE_REQ_TESTS, SignF_Blank_Message_Test)
{
    EXPECT_FALSE(msg_term->SignF(pvkeyfile));
}

TEST_F(SRUP_TERMINATE_REQ_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_term->Sign(pvkey));
}

TEST_F(SRUP_TERMINATE_REQ_TESTS, SignF_Complete_Message_Test)
{
    msg_term->token(token, token_length);
    msg_term->sequenceID(sequence_ID);
    msg_term->senderID(sender_ID);
    EXPECT_TRUE(msg_term->SignF(pvkeyfile));
}

TEST_F(SRUP_TERMINATE_REQ_TESTS, Sign_Complete_Message_Test)
{
    msg_term->token(token, token_length);
    msg_term->sequenceID(sequence_ID);
    msg_term->senderID(sender_ID);
    EXPECT_TRUE(msg_term->Sign(pvkey));
}

TEST_F(SRUP_TERMINATE_REQ_TESTS, SignF_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_term->SignF(pvkeyfile));
    msg_term->token(token, token_length);
    EXPECT_FALSE(msg_term->SignF(pvkeyfile));
    msg_term->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_term->SignF(pvkeyfile));
    msg_term->senderID(sender_ID);
    EXPECT_TRUE(msg_term->SignF(pvkeyfile));
}

TEST_F(SRUP_TERMINATE_REQ_TESTS, Sign_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_term->Sign(pvkey));
    msg_term->token(token, token_length);
    EXPECT_FALSE(msg_term->Sign(pvkey));
    msg_term->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_term->Sign(pvkey));
    msg_term->senderID(sender_ID);
    EXPECT_TRUE(msg_term->Sign(pvkey));
}

TEST_F(SRUP_TERMINATE_REQ_TESTS, SignF_and_VerifyF_Message_Test)
{
    msg_term->token(token, token_length);
    msg_term->sequenceID(sequence_ID);
    msg_term->senderID(sender_ID);

    EXPECT_TRUE(msg_term->SignF(pvkeyfile));

    uint8_t msg_type;
    msg_type = *msg_term->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_TERMINATE_CMD);

    r_serial_data = msg_term->Serialized();
    sz = msg_term->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_term2 = new SRUP_MSG_TERMINATE_CMD;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_term2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_term2->VerifyF(pbkeyfile));

    char* recieved_token;
    recieved_token = (char*) msg_term2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_term2->token(token, token_length);

    recieved_token = (char*) msg_term2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_term2->VerifyF(pbkeyfile));

    delete(msg_term2);
    delete(s_serial_data);
}

TEST_F(SRUP_TERMINATE_REQ_TESTS, Sign_and_Verify_Message_Test)
{
    msg_term->token(token, token_length);
    msg_term->sequenceID(sequence_ID);
    msg_term->senderID(sender_ID);

    EXPECT_TRUE(msg_term->Sign(pvkey));

    uint8_t msg_type;
    msg_type = *msg_term->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_TERMINATE_CMD);

    r_serial_data = msg_term->Serialized();
    sz = msg_term->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_term2 = new SRUP_MSG_TERMINATE_CMD;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_term2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_term2->Verify(pbkey));

    char* recieved_token;
    recieved_token = (char*) msg_term2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_term2->token(token, token_length);

    recieved_token = (char*) msg_term2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_term2->Verify(pbkey));

    delete(msg_term2);
    delete(s_serial_data);
}

TEST_F(SRUP_TERMINATE_REQ_TESTS, Generic_Deserialize_Test)
{
    msg_term->token(token, token_length);
    msg_term->sequenceID(sequence_ID);
    msg_term->senderID(sender_ID);

    EXPECT_TRUE(msg_term->SignF(pvkeyfile));

    r_serial_data = msg_term->Serialized();
    sz = msg_term->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    EXPECT_TRUE(msg_term->Sign(pvkey));

    r_serial_data = msg_term->Serialized();
    sz = msg_term->SerializedLength();
    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    delete(msg_generic);
    delete(s_serial_data);
}

// ********************************
// DEREGISTER_REQ_TESTS
// ********************************

class SRUP_DEREGISTER_REQ_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_DEREGISTER_REQ *msg_dereg_req;
    SRUP_MSG_DEREGISTER_REQ *msg_dereg_req2;

    uint8_t* token;
    uint16_t token_length;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pbkey;
    char* pvkey;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

protected:

    virtual void TearDown()
    {
        delete[] token;
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pbkey;
        delete[] pvkey;

        delete(sequence_ID);
        delete(sender_ID);
        delete(msg_dereg_req);
    }

    virtual void SetUp()
    {
        msg_dereg_req = new SRUP_MSG_DEREGISTER_REQ;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 555ULL;
    }
};

TEST_F(SRUP_DEREGISTER_REQ_TESTS, SignF_Blank_Message_Test)
{
    EXPECT_FALSE(msg_dereg_req->SignF(pvkeyfile));
}

TEST_F(SRUP_DEREGISTER_REQ_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_dereg_req->Sign(pvkey));
}

TEST_F(SRUP_DEREGISTER_REQ_TESTS, SignF_Complete_Message_Test)
{
    msg_dereg_req->token(token, token_length);
    msg_dereg_req->sequenceID(sequence_ID);
    msg_dereg_req->senderID(sender_ID);
    EXPECT_TRUE(msg_dereg_req->SignF(pvkeyfile));
}

TEST_F(SRUP_DEREGISTER_REQ_TESTS, Sign_Complete_Message_Test)
{
    msg_dereg_req->token(token, token_length);
    msg_dereg_req->sequenceID(sequence_ID);
    msg_dereg_req->senderID(sender_ID);
    EXPECT_TRUE(msg_dereg_req->Sign(pvkey));
}

TEST_F(SRUP_DEREGISTER_REQ_TESTS, SignF_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_dereg_req->SignF(pvkeyfile));
    msg_dereg_req->token(token, token_length);
    EXPECT_FALSE(msg_dereg_req->SignF(pvkeyfile));
    msg_dereg_req->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_dereg_req->SignF(pvkeyfile));
    msg_dereg_req->senderID(sender_ID);
    EXPECT_TRUE(msg_dereg_req->SignF(pvkeyfile));
}

TEST_F(SRUP_DEREGISTER_REQ_TESTS, Sign_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_dereg_req->Sign(pvkey));
    msg_dereg_req->token(token, token_length);
    EXPECT_FALSE(msg_dereg_req->Sign(pvkey));
    msg_dereg_req->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_dereg_req->Sign(pvkey));
    msg_dereg_req->senderID(sender_ID);
    EXPECT_TRUE(msg_dereg_req->Sign(pvkey));
}

TEST_F(SRUP_DEREGISTER_REQ_TESTS, SignF_and_VerifyF_Message_Test)
{
    msg_dereg_req->token(token, token_length);
    msg_dereg_req->sequenceID(sequence_ID);
    msg_dereg_req->senderID(sender_ID);

    EXPECT_TRUE(msg_dereg_req->SignF(pvkeyfile));

    uint8_t msg_type;
    msg_type = *msg_dereg_req->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_DEREGISTER_REQ);

    r_serial_data = msg_dereg_req->Serialized();
    sz = msg_dereg_req->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_dereg_req2 = new SRUP_MSG_DEREGISTER_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_dereg_req2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_dereg_req2->VerifyF(pbkeyfile));

    char* recieved_token;
    recieved_token = (char*) msg_dereg_req2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_dereg_req2->token(token, token_length);

    recieved_token = (char*) msg_dereg_req2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_dereg_req2->VerifyF(pbkeyfile));

    delete(msg_dereg_req2);
    delete(s_serial_data);
}

TEST_F(SRUP_DEREGISTER_REQ_TESTS, Sign_and_Verify_Message_Test)
{
    msg_dereg_req->token(token, token_length);
    msg_dereg_req->sequenceID(sequence_ID);
    msg_dereg_req->senderID(sender_ID);

    EXPECT_TRUE(msg_dereg_req->Sign(pvkey));

    uint8_t msg_type;
    msg_type = *msg_dereg_req->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_DEREGISTER_REQ);

    r_serial_data = msg_dereg_req->Serialized();
    sz = msg_dereg_req->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_dereg_req2 = new SRUP_MSG_DEREGISTER_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_dereg_req2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_dereg_req2->Verify(pbkey));

    char* recieved_token;
    recieved_token = (char*) msg_dereg_req2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_dereg_req2->token(token, token_length);

    recieved_token = (char*) msg_dereg_req2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_dereg_req2->Verify(pbkey));

    delete(msg_dereg_req2);
    delete(s_serial_data);
}

TEST_F(SRUP_DEREGISTER_REQ_TESTS, Generic_Deserialize_Test)
{
    msg_dereg_req->token(token, token_length);
    msg_dereg_req->sequenceID(sequence_ID);
    msg_dereg_req->senderID(sender_ID);

    EXPECT_TRUE(msg_dereg_req->Sign(pvkey));

    r_serial_data = msg_dereg_req->Serialized();
    sz = msg_dereg_req->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    EXPECT_TRUE(msg_dereg_req->Sign(pvkey));

    r_serial_data = msg_dereg_req->Serialized();
    sz = msg_dereg_req->SerializedLength();
    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    delete(msg_generic);
    delete(s_serial_data);
}
// ********************************
// DEREGISTER_CMD_TESTS
// ********************************

class SRUP_DEREGISTER_CMD_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_DEREGISTER_CMD *msg_dereg_req;
    SRUP_MSG_DEREGISTER_CMD *msg_dereg_req2;

    uint8_t* token;
    uint16_t token_length;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pvkey;
    char* pbkey;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

protected:

    virtual void TearDown()
    {
        delete[] token;
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pbkey;
        delete[] pvkey;

        delete(sequence_ID);
        delete(sender_ID);
        delete(msg_dereg_req);
    }

    virtual void SetUp()
    {
        msg_dereg_req = new SRUP_MSG_DEREGISTER_CMD;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 555ULL;
    }
};

TEST_F(SRUP_DEREGISTER_CMD_TESTS, SignF_Blank_Message_Test)
{
    EXPECT_FALSE(msg_dereg_req->SignF(pvkeyfile));
}

TEST_F(SRUP_DEREGISTER_CMD_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_dereg_req->Sign(pvkey));
}

TEST_F(SRUP_DEREGISTER_CMD_TESTS, SignF_Complete_Message_Test)
{
    msg_dereg_req->token(token, token_length);
    msg_dereg_req->sequenceID(sequence_ID);
    msg_dereg_req->senderID(sender_ID);
    EXPECT_TRUE(msg_dereg_req->SignF(pvkeyfile));
}

TEST_F(SRUP_DEREGISTER_CMD_TESTS, Sign_Complete_Message_Test)
{
    msg_dereg_req->token(token, token_length);
    msg_dereg_req->sequenceID(sequence_ID);
    msg_dereg_req->senderID(sender_ID);
    EXPECT_TRUE(msg_dereg_req->Sign(pvkey));
}

TEST_F(SRUP_DEREGISTER_CMD_TESTS, SignF_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_dereg_req->SignF(pvkeyfile));
    msg_dereg_req->token(token, token_length);
    EXPECT_FALSE(msg_dereg_req->SignF(pvkeyfile));
    msg_dereg_req->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_dereg_req->SignF(pvkeyfile));
    msg_dereg_req->senderID(sender_ID);
    EXPECT_TRUE(msg_dereg_req->SignF(pvkeyfile));
}

TEST_F(SRUP_DEREGISTER_CMD_TESTS, Sign_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_dereg_req->Sign(pvkey));
    msg_dereg_req->token(token, token_length);
    EXPECT_FALSE(msg_dereg_req->Sign(pvkey));
    msg_dereg_req->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_dereg_req->Sign(pvkey));
    msg_dereg_req->senderID(sender_ID);
    EXPECT_TRUE(msg_dereg_req->Sign(pvkey));
}

TEST_F(SRUP_DEREGISTER_CMD_TESTS, SignF_and_VerifyF_Message_Test)
{
    msg_dereg_req->token(token, token_length);
    msg_dereg_req->sequenceID(sequence_ID);
    msg_dereg_req->senderID(sender_ID);

    EXPECT_TRUE(msg_dereg_req->SignF(pvkeyfile));

    uint8_t msg_type;
    msg_type = *msg_dereg_req->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_DEREGISTER_CMD);

    r_serial_data = msg_dereg_req->Serialized();
    sz = msg_dereg_req->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_dereg_req2 = new SRUP_MSG_DEREGISTER_CMD;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_dereg_req2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_dereg_req2->VerifyF(pbkeyfile));

    char* recieved_token;
    recieved_token = (char*) msg_dereg_req2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_dereg_req2->token(token, token_length);

    recieved_token = (char*) msg_dereg_req2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_dereg_req2->VerifyF(pbkeyfile));

    delete(msg_dereg_req2);
    delete(s_serial_data);
}

TEST_F(SRUP_DEREGISTER_CMD_TESTS, Sign_and_Verify_Message_Test)
{
    msg_dereg_req->token(token, token_length);
    msg_dereg_req->sequenceID(sequence_ID);
    msg_dereg_req->senderID(sender_ID);

    EXPECT_TRUE(msg_dereg_req->Sign(pvkey));

    uint8_t msg_type;
    msg_type = *msg_dereg_req->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_DEREGISTER_CMD);

    r_serial_data = msg_dereg_req->Serialized();
    sz = msg_dereg_req->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_dereg_req2 = new SRUP_MSG_DEREGISTER_CMD;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_dereg_req2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_dereg_req2->Verify(pbkey));

    char* recieved_token;
    recieved_token = (char*) msg_dereg_req2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_dereg_req2->token(token, token_length);

    recieved_token = (char*) msg_dereg_req2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_dereg_req2->Verify(pbkey));

    delete(msg_dereg_req2);
    delete(s_serial_data);
}

TEST_F(SRUP_DEREGISTER_CMD_TESTS, Generic_Deserialize_Test)
{
    msg_dereg_req->token(token, token_length);
    msg_dereg_req->sequenceID(sequence_ID);
    msg_dereg_req->senderID(sender_ID);

    EXPECT_TRUE(msg_dereg_req->SignF(pvkeyfile));

    r_serial_data = msg_dereg_req->Serialized();
    sz = msg_dereg_req->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    EXPECT_TRUE(msg_dereg_req->Sign(pvkey));

    r_serial_data = msg_dereg_req->Serialized();
    sz = msg_dereg_req->SerializedLength();
    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    delete(msg_generic);
    delete(s_serial_data);
}


// ********************************
// OBSERVED_JOIN_REQ_TESTS
// ********************************

class SRUP_OBS_JOIN_REQ_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_OBSERVED_JOIN_REQ *msg_obs_join;
    SRUP_MSG_OBSERVED_JOIN_REQ *msg_obs_join2;

    uint8_t* token;
    uint16_t token_length;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pbkey;
    char* pvkey;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;
    uint64_t* observer_ID;

protected:

    virtual void TearDown()
    {
        delete[] token;
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pbkey;
        delete[] pvkey;

        delete(sequence_ID);
        delete(sender_ID);
        delete(observer_ID);
        delete(msg_obs_join);
    }

    virtual void SetUp()
    {
        msg_obs_join = new SRUP_MSG_OBSERVED_JOIN_REQ;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 555ULL;

        observer_ID = new uint64_t;
        *observer_ID = OBS_ID;
    }
};

TEST_F(SRUP_OBS_JOIN_REQ_TESTS, SignF_Blank_Message_Test)
{
    EXPECT_FALSE(msg_obs_join->SignF(pvkeyfile));
}

TEST_F(SRUP_OBS_JOIN_REQ_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_obs_join->Sign(pvkey));
}


TEST_F(SRUP_OBS_JOIN_REQ_TESTS, SignF_Complete_Message_Test)
{
    msg_obs_join->token(token, token_length);
    msg_obs_join->sequenceID(sequence_ID);
    msg_obs_join->senderID(sender_ID);
    msg_obs_join->observer_ID(observer_ID);
    EXPECT_TRUE(msg_obs_join->SignF(pvkeyfile));
}

TEST_F(SRUP_OBS_JOIN_REQ_TESTS, Sign_Complete_Message_Test)
{
    msg_obs_join->token(token, token_length);
    msg_obs_join->sequenceID(sequence_ID);
    msg_obs_join->senderID(sender_ID);
    msg_obs_join->observer_ID(observer_ID);
    EXPECT_TRUE(msg_obs_join->Sign(pvkey));
}

TEST_F(SRUP_OBS_JOIN_REQ_TESTS, SignF_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_obs_join->SignF(pvkeyfile));
    msg_obs_join->token(token, token_length);
    EXPECT_FALSE(msg_obs_join->SignF(pvkeyfile));
    msg_obs_join->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_obs_join->SignF(pvkeyfile));
    msg_obs_join->senderID(sender_ID);
    EXPECT_FALSE(msg_obs_join->SignF(pvkeyfile));
    msg_obs_join->observer_ID(observer_ID);
    EXPECT_TRUE(msg_obs_join->SignF(pvkeyfile));
}

TEST_F(SRUP_OBS_JOIN_REQ_TESTS, Sign_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_obs_join->Sign(pvkey));
    msg_obs_join->token(token, token_length);
    EXPECT_FALSE(msg_obs_join->Sign(pvkey));
    msg_obs_join->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_obs_join->Sign(pvkey));
    msg_obs_join->senderID(sender_ID);
    EXPECT_FALSE(msg_obs_join->Sign(pvkey));
    msg_obs_join->observer_ID(observer_ID);
    EXPECT_TRUE(msg_obs_join->Sign(pvkey));
}

TEST_F(SRUP_OBS_JOIN_REQ_TESTS, SignF_and_VerifyF_Message_Test)
{
    msg_obs_join->token(token, token_length);
    msg_obs_join->sequenceID(sequence_ID);
    msg_obs_join->senderID(sender_ID);
    msg_obs_join->observer_ID(observer_ID);

    EXPECT_TRUE(msg_obs_join->SignF(pvkeyfile));

    uint8_t msg_type;
    msg_type = *msg_obs_join->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_OBS_JOIN_REQ);

    r_serial_data = msg_obs_join->Serialized();
    sz = msg_obs_join->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=8; // observer_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_obs_join2 = new SRUP_MSG_OBSERVED_JOIN_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_obs_join2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_obs_join2->VerifyF(pbkeyfile));

    char* recieved_token;
    recieved_token = (char*) msg_obs_join2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_obs_join2->token(token, token_length);

    recieved_token = (char*) msg_obs_join2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_obs_join2->VerifyF(pbkeyfile));

    delete(msg_obs_join2);
    delete(s_serial_data);
}

TEST_F(SRUP_OBS_JOIN_REQ_TESTS, Sign_and_Verify_Message_Test)
{
    msg_obs_join->token(token, token_length);
    msg_obs_join->sequenceID(sequence_ID);
    msg_obs_join->senderID(sender_ID);
    msg_obs_join->observer_ID(observer_ID);

    EXPECT_TRUE(msg_obs_join->Sign(pvkey));

    uint8_t msg_type;
    msg_type = *msg_obs_join->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_OBS_JOIN_REQ);

    r_serial_data = msg_obs_join->Serialized();
    sz = msg_obs_join->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=8; // observer_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    msg_obs_join2 = new SRUP_MSG_OBSERVED_JOIN_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_obs_join2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_obs_join2->Verify(pbkey));

    char* recieved_token;
    recieved_token = (char*) msg_obs_join2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_obs_join2->token(token, token_length);

    recieved_token = (char*) msg_obs_join2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_obs_join2->Verify(pbkey));

    delete(msg_obs_join2);
    delete(s_serial_data);
}

TEST_F(SRUP_OBS_JOIN_REQ_TESTS, Generic_Deserialize_Test)
{
    msg_obs_join->token(token, token_length);
    msg_obs_join->sequenceID(sequence_ID);
    msg_obs_join->senderID(sender_ID);
    msg_obs_join->observer_ID(observer_ID);

    EXPECT_TRUE(msg_obs_join->SignF(pvkeyfile));

    r_serial_data = msg_obs_join->Serialized();
    sz = msg_obs_join->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=8; // observer_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=token_length;

    EXPECT_EQ(sz, expected_size);

    EXPECT_TRUE(msg_obs_join->Sign(pvkey));

    r_serial_data = msg_obs_join->Serialized();
    sz = msg_obs_join->SerializedLength();
    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    delete(msg_generic);
    delete(s_serial_data);
}

TEST_F(SRUP_OBS_JOIN_REQ_TESTS, Serialize_Observer_ID_F)
{
    msg_obs_join->sequenceID(sequence_ID);
    msg_obs_join->token(token, token_length);
    msg_obs_join->senderID(sender_ID);
    msg_obs_join->observer_ID(observer_ID);

    msg_obs_join->SignF(pvkeyfile);

    r_serial_data = msg_obs_join->Serialized();
    sz = msg_obs_join->SerializedLength();

    msg_obs_join2 = new SRUP_MSG_OBSERVED_JOIN_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);
    msg_obs_join2->DeSerialize(s_serial_data);
    const uint64_t* snd2 = msg_obs_join2->senderID();
    EXPECT_TRUE(*snd2 == *sender_ID);

    const uint64_t* obs2 = msg_obs_join->observer_ID();
    EXPECT_TRUE(*obs2 == *observer_ID);

    delete (msg_obs_join2);
    delete(s_serial_data);
}

TEST_F(SRUP_OBS_JOIN_REQ_TESTS, Serialize_Observer_ID)
{
    msg_obs_join->sequenceID(sequence_ID);
    msg_obs_join->token(token, token_length);
    msg_obs_join->senderID(sender_ID);
    msg_obs_join->observer_ID(observer_ID);

    msg_obs_join->Sign(pvkey);

    r_serial_data = msg_obs_join->Serialized();
    sz = msg_obs_join->SerializedLength();

    msg_obs_join2 = new SRUP_MSG_OBSERVED_JOIN_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);
    msg_obs_join2->DeSerialize(s_serial_data);
    const uint64_t* snd2 = msg_obs_join2->senderID();
    EXPECT_TRUE(*snd2 == *sender_ID);

    const uint64_t* obs2 = msg_obs_join->observer_ID();
    EXPECT_TRUE(*obs2 == *observer_ID);

    delete (msg_obs_join2);
    delete(s_serial_data);
    }

// ********************************
// JOIN_HUMAN_RESP_TESTS
// ********************************

class SRUP_HUMAN_JOIN_RESP_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_HUMAN_JOIN_RESP *msg_join_resp;
    SRUP_MSG_HUMAN_JOIN_RESP *msg_join_resp2;

    uint8_t* token;
    uint16_t token_length;
    uint8_t* encrypted_data;
    uint16_t encrypted_data_length;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pvkey;
    char* pbkey;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

protected:

    virtual void TearDown()
    {
        delete[] token;
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pvkey;
        delete[] pbkey;

        delete(sequence_ID);
        delete(sender_ID);
        delete[] encrypted_data;
        delete(msg_join_resp);
    }

    virtual void SetUp()
    {
        msg_join_resp = new SRUP_MSG_HUMAN_JOIN_RESP;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 555ULL;

        encrypted_data = new uint8_t[16];

        encrypted_data[0x0] = 0x33;
        encrypted_data[0x1] = 0x44;
        encrypted_data[0x2] = 0x55;
        encrypted_data[0x3] = 0x66;
        encrypted_data[0x4] = 0x77;
        encrypted_data[0x5] = 0x88;
        encrypted_data[0x6] = 0x99;
        encrypted_data[0x7] = 0xAA;
        encrypted_data[0x8] = 0xBB;
        encrypted_data[0x9] = 0xCC;
        encrypted_data[0xA] = 0xDD;
        encrypted_data[0xB] = 0xEE;
        encrypted_data[0xC] = 0xFF;
        encrypted_data[0xD] = 0x00;
        encrypted_data[0xE] = 0x11;
        encrypted_data[0xF] = 0x22;

        encrypted_data_length = 16;
    }
};

TEST_F(SRUP_HUMAN_JOIN_RESP_TESTS, SignF_Blank_Message_Test)
{
    EXPECT_FALSE(msg_join_resp->SignF(pvkeyfile));
}

TEST_F(SRUP_HUMAN_JOIN_RESP_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_join_resp->Sign(pvkey));
}

TEST_F(SRUP_HUMAN_JOIN_RESP_TESTS, SignF_Complete_Message_Test)
{
    msg_join_resp->token(token, token_length);
    msg_join_resp->sequenceID(sequence_ID);
    msg_join_resp->senderID(sender_ID);
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, false, pbkeyfile);
    EXPECT_TRUE(msg_join_resp->SignF(pvkeyfile));
}

TEST_F(SRUP_HUMAN_JOIN_RESP_TESTS, Sign_Complete_Message_Test)
{
    msg_join_resp->token(token, token_length);
    msg_join_resp->sequenceID(sequence_ID);
    msg_join_resp->senderID(sender_ID);
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, true, pbkey);
    EXPECT_TRUE(msg_join_resp->Sign(pvkey));
}

TEST_F(SRUP_HUMAN_JOIN_RESP_TESTS, SignF_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_join_resp->SignF(pvkeyfile));
    msg_join_resp->token(token, token_length);
    EXPECT_FALSE(msg_join_resp->SignF(pvkeyfile));
    msg_join_resp->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_join_resp->SignF(pvkeyfile));
    msg_join_resp->senderID(sender_ID);
    EXPECT_FALSE(msg_join_resp->SignF(pvkeyfile));
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, false, pbkeyfile);
    EXPECT_TRUE(msg_join_resp->SignF(pvkeyfile));
}

TEST_F(SRUP_HUMAN_JOIN_RESP_TESTS, Sign_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_join_resp->Sign(pvkey));
    msg_join_resp->token(token, token_length);
    EXPECT_FALSE(msg_join_resp->Sign(pvkey));
    msg_join_resp->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_join_resp->Sign(pvkey));
    msg_join_resp->senderID(sender_ID);
    EXPECT_FALSE(msg_join_resp->Sign(pvkey));
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, true, pbkey);
    EXPECT_TRUE(msg_join_resp->Sign(pvkey));
}

TEST_F(SRUP_HUMAN_JOIN_RESP_TESTS, SignF_and_VerifyF_Message_Test)
{
    msg_join_resp->token(token, token_length);
    msg_join_resp->sequenceID(sequence_ID);
    msg_join_resp->senderID(sender_ID);
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, false, pbkeyfile);

    EXPECT_TRUE(msg_join_resp->SignF(pvkeyfile));
    EXPECT_TRUE(msg_join_resp->VerifyF(pbkeyfile));

    uint8_t msg_type;
    msg_type = *msg_join_resp->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_HM_JOIN_RESP);

    r_serial_data = msg_join_resp->Serialized();
    sz = msg_join_resp->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*3); // 2-byte sizes for 3 variable-length fields
    expected_size+=token_length;
    expected_size+=316; // EncryptFed Data Length...

    EXPECT_EQ(sz, expected_size);

    msg_join_resp2 = new SRUP_MSG_HUMAN_JOIN_RESP;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_join_resp2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_join_resp2->VerifyF(pbkeyfile));

    char* recieved_token;
    recieved_token = (char*) msg_join_resp2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_join_resp2->token(token, token_length);

    recieved_token = (char*) msg_join_resp2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_join_resp2->VerifyF(pbkeyfile));

    delete(msg_join_resp2);
    delete(s_serial_data);
}

TEST_F(SRUP_HUMAN_JOIN_RESP_TESTS, Sign_and_Verify_Message_Test)
{
    msg_join_resp->token(token, token_length);
    msg_join_resp->sequenceID(sequence_ID);
    msg_join_resp->senderID(sender_ID);
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, true, pbkey);

    EXPECT_TRUE(msg_join_resp->Sign(pvkey));
    EXPECT_TRUE(msg_join_resp->Verify(pbkey));

    uint8_t msg_type;
    msg_type = *msg_join_resp->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_HM_JOIN_RESP);

    r_serial_data = msg_join_resp->Serialized();
    sz = msg_join_resp->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*3); // 2-byte sizes for 3 variable-length fields
    expected_size+=token_length;
    expected_size+=316; // EncryptFed Data Length...

    EXPECT_EQ(sz, expected_size);

    msg_join_resp2 = new SRUP_MSG_HUMAN_JOIN_RESP;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_join_resp2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_join_resp2->Verify(pbkey));

    char* recieved_token;
    recieved_token = (char*) msg_join_resp2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_join_resp2->token(token, token_length);

    recieved_token = (char*) msg_join_resp2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_join_resp2->Verify(pbkey));

    delete(msg_join_resp2);
    delete(s_serial_data);
}

TEST_F(SRUP_HUMAN_JOIN_RESP_TESTS, Generic_Deserialize_Test_F)
{
    msg_join_resp->token(token, token_length);
    msg_join_resp->sequenceID(sequence_ID);
    msg_join_resp->senderID(sender_ID);
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, false, pbkeyfile);

    EXPECT_TRUE(msg_join_resp->SignF(pvkeyfile));
    EXPECT_TRUE(msg_join_resp->VerifyF(pbkeyfile));

    r_serial_data = msg_join_resp->Serialized();
    sz = msg_join_resp->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*3); // 2-byte sizes for 3 variable-length fields
    expected_size+=token_length;
    expected_size+=316; // EncryptFed Data Length...

    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    delete(msg_generic);
    delete(s_serial_data);
}

TEST_F(SRUP_HUMAN_JOIN_RESP_TESTS, Generic_Deserialize_Test)
{
    msg_join_resp->token(token, token_length);
    msg_join_resp->sequenceID(sequence_ID);
    msg_join_resp->senderID(sender_ID);
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, true, pbkey);

    EXPECT_TRUE(msg_join_resp->Sign(pvkey));
    EXPECT_TRUE(msg_join_resp->Verify(pbkey));

    r_serial_data = msg_join_resp->Serialized();
    sz = msg_join_resp->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*3); // 2-byte sizes for 3 variable-length fields
    expected_size+=token_length;
    expected_size+=316; // EncryptFed Data Length...

    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    delete(msg_generic);
    delete(s_serial_data);
}

TEST_F(SRUP_HUMAN_JOIN_RESP_TESTS, DecryptF_Data_Test)
{
    msg_join_resp->token(token, token_length);
    msg_join_resp->sequenceID(sequence_ID);
    msg_join_resp->senderID(sender_ID);
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, false, pbkeyfile);

    EXPECT_TRUE(msg_join_resp->SignF(pvkeyfile));

    uint8_t* comparison_data;
    comparison_data = (uint8_t*) msg_join_resp->encrypted_data(false, pvkeyfile);
    EXPECT_EQ(*comparison_data, *encrypted_data);

    r_serial_data = msg_join_resp->Serialized();
    sz = msg_join_resp->SerializedLength();

    msg_join_resp2 = new SRUP_MSG_HUMAN_JOIN_RESP;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_join_resp2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_join_resp2->VerifyF(pbkeyfile));

    comparison_data = (uint8_t*) msg_join_resp2->encrypted_data(false, pvkeyfile);

    EXPECT_EQ(*comparison_data, *encrypted_data);

    delete(msg_join_resp2);
    delete(s_serial_data);
}

TEST_F(SRUP_HUMAN_JOIN_RESP_TESTS, Decrypt_Data_Test)
{
    msg_join_resp->token(token, token_length);
    msg_join_resp->sequenceID(sequence_ID);
    msg_join_resp->senderID(sender_ID);
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, true, pbkey);

    EXPECT_TRUE(msg_join_resp->Sign(pvkey));

    uint8_t* comparison_data;
    comparison_data = (uint8_t*) msg_join_resp->encrypted_data(true, pvkey);
    EXPECT_EQ(*comparison_data, *encrypted_data);

    r_serial_data = msg_join_resp->Serialized();
    sz = msg_join_resp->SerializedLength();

    msg_join_resp2 = new SRUP_MSG_HUMAN_JOIN_RESP;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_join_resp2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_join_resp2->Verify(pbkey));

    comparison_data = (uint8_t*) msg_join_resp2->encrypted_data(true, pvkey);

    EXPECT_EQ(*comparison_data, *encrypted_data);

    delete(msg_join_resp2);
    delete(s_serial_data);
}

// ********************************
// JOIN_OBS_RESP_TESTS
// ********************************

class SRUP_OBS_JOIN_RESP_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_OBS_JOIN_RESP *msg_join_resp;
    SRUP_MSG_OBS_JOIN_RESP *msg_join_resp2;

    uint8_t* token;
    uint16_t token_length;
    uint8_t* encrypted_data;
    uint16_t encrypted_data_length;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pbkey;
    char* pvkey;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

protected:

    virtual void TearDown()
    {
        delete[] token;
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pbkey;
        delete[] pvkey;

        delete(sequence_ID);
        delete(sender_ID);
        delete[] encrypted_data;
        delete(msg_join_resp);
    }

    virtual void SetUp()
    {
        msg_join_resp = new SRUP_MSG_OBS_JOIN_RESP;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 555ULL;

        encrypted_data = new uint8_t[16];

        encrypted_data[0x0] = 0x33;
        encrypted_data[0x1] = 0x44;
        encrypted_data[0x2] = 0x55;
        encrypted_data[0x3] = 0x66;
        encrypted_data[0x4] = 0x77;
        encrypted_data[0x5] = 0x88;
        encrypted_data[0x6] = 0x99;
        encrypted_data[0x7] = 0xAA;
        encrypted_data[0x8] = 0xBB;
        encrypted_data[0x9] = 0xCC;
        encrypted_data[0xA] = 0xDD;
        encrypted_data[0xB] = 0xEE;
        encrypted_data[0xC] = 0xFF;
        encrypted_data[0xD] = 0x00;
        encrypted_data[0xE] = 0x11;
        encrypted_data[0xF] = 0x22;

        encrypted_data_length = 16;
    }
};

TEST_F(SRUP_OBS_JOIN_RESP_TESTS, SignF_Blank_Message_Test)
{
    EXPECT_FALSE(msg_join_resp->SignF(pvkeyfile));
}

TEST_F(SRUP_OBS_JOIN_RESP_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_join_resp->Sign(pvkey));
}

TEST_F(SRUP_OBS_JOIN_RESP_TESTS, SignF_Complete_Message_Test)
{
    msg_join_resp->token(token, token_length);
    msg_join_resp->sequenceID(sequence_ID);
    msg_join_resp->senderID(sender_ID);
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, false, pbkeyfile);
    EXPECT_TRUE(msg_join_resp->SignF(pvkeyfile));
}

TEST_F(SRUP_OBS_JOIN_RESP_TESTS, Sign_Complete_Message_Test)
{
    msg_join_resp->token(token, token_length);
    msg_join_resp->sequenceID(sequence_ID);
    msg_join_resp->senderID(sender_ID);
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, true, pbkey);
    EXPECT_TRUE(msg_join_resp->Sign(pvkey));
}

TEST_F(SRUP_OBS_JOIN_RESP_TESTS, SignF_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_join_resp->SignF(pvkeyfile));
    msg_join_resp->token(token, token_length);
    EXPECT_FALSE(msg_join_resp->SignF(pvkeyfile));
    msg_join_resp->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_join_resp->SignF(pvkeyfile));
    msg_join_resp->senderID(sender_ID);
    EXPECT_FALSE(msg_join_resp->SignF(pvkeyfile));
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, false, pbkeyfile);
    EXPECT_TRUE(msg_join_resp->SignF(pvkeyfile));
}

TEST_F(SRUP_OBS_JOIN_RESP_TESTS, Sign_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_join_resp->Sign(pvkey));
    msg_join_resp->token(token, token_length);
    EXPECT_FALSE(msg_join_resp->Sign(pvkey));
    msg_join_resp->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_join_resp->Sign(pvkey));
    msg_join_resp->senderID(sender_ID);
    EXPECT_FALSE(msg_join_resp->Sign(pvkey));
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, true, pbkey);
    EXPECT_TRUE(msg_join_resp->Sign(pvkey));
}

TEST_F(SRUP_OBS_JOIN_RESP_TESTS, SignF_and_VerifyF_Message_Test)
{
    msg_join_resp->token(token, token_length);
    msg_join_resp->sequenceID(sequence_ID);
    msg_join_resp->senderID(sender_ID);
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, false, pbkeyfile);

    EXPECT_TRUE(msg_join_resp->SignF(pvkeyfile));
    EXPECT_TRUE(msg_join_resp->VerifyF(pbkeyfile));

    uint8_t msg_type;
    msg_type = *msg_join_resp->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_OBS_JOIN_RESP);

    r_serial_data = msg_join_resp->Serialized();
    sz = msg_join_resp->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*3); // 2-byte sizes for 3 variable-length fields
    expected_size+=token_length;
    expected_size+=316; // EncryptFed Data Length...

    EXPECT_EQ(sz, expected_size);

    msg_join_resp2 = new SRUP_MSG_OBS_JOIN_RESP;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_join_resp2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_join_resp2->VerifyF(pbkeyfile));

    char* recieved_token;
    recieved_token = (char*) msg_join_resp2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_join_resp2->token(token, token_length);

    recieved_token = (char*) msg_join_resp2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_join_resp2->VerifyF(pbkeyfile));

    delete(msg_join_resp2);
    delete(s_serial_data);
}

TEST_F(SRUP_OBS_JOIN_RESP_TESTS, Sign_and_Verify_Message_Test)
{
    msg_join_resp->token(token, token_length);
    msg_join_resp->sequenceID(sequence_ID);
    msg_join_resp->senderID(sender_ID);
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, true, pbkey);

    EXPECT_TRUE(msg_join_resp->Sign(pvkey));
    EXPECT_TRUE(msg_join_resp->Verify(pbkey));

    uint8_t msg_type;
    msg_type = *msg_join_resp->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_OBS_JOIN_RESP);

    r_serial_data = msg_join_resp->Serialized();
    sz = msg_join_resp->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*3); // 2-byte sizes for 3 variable-length fields
    expected_size+=token_length;
    expected_size+=316; // EncryptFed Data Length...

    EXPECT_EQ(sz, expected_size);

    msg_join_resp2 = new SRUP_MSG_OBS_JOIN_RESP;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_join_resp2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_join_resp2->Verify(pbkey));

    char* recieved_token;
    recieved_token = (char*) msg_join_resp2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_join_resp2->token(token, token_length);

    recieved_token = (char*) msg_join_resp2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_join_resp2->Verify(pbkey));

    delete(msg_join_resp2);
    delete(s_serial_data);
}

TEST_F(SRUP_OBS_JOIN_RESP_TESTS, Generic_Deserialize_Test_F)
{
    msg_join_resp->token(token, token_length);
    msg_join_resp->sequenceID(sequence_ID);
    msg_join_resp->senderID(sender_ID);
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, false, pbkeyfile);

    EXPECT_TRUE(msg_join_resp->SignF(pvkeyfile));
    EXPECT_TRUE(msg_join_resp->VerifyF(pbkeyfile));

    r_serial_data = msg_join_resp->Serialized();
    sz = msg_join_resp->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*3); // 2-byte sizes for 3 variable-length fields
    expected_size+=token_length;
    expected_size+=316; // EncryptFed Data Length...

    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    delete(msg_generic);
    delete(s_serial_data);
}

TEST_F(SRUP_OBS_JOIN_RESP_TESTS, Generic_Deserialize_Test)
{
    msg_join_resp->token(token, token_length);
    msg_join_resp->sequenceID(sequence_ID);
    msg_join_resp->senderID(sender_ID);
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, true, pbkey);

    EXPECT_TRUE(msg_join_resp->Sign(pvkey));
    EXPECT_TRUE(msg_join_resp->Verify(pbkey));

    r_serial_data = msg_join_resp->Serialized();
    sz = msg_join_resp->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*3); // 2-byte sizes for 3 variable-length fields
    expected_size+=token_length;
    expected_size+=316; // EncryptFed Data Length...

    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    delete(msg_generic);
    delete(s_serial_data);
}

TEST_F(SRUP_OBS_JOIN_RESP_TESTS, DecryptF_Data_Test)
{
    msg_join_resp->token(token, token_length);
    msg_join_resp->sequenceID(sequence_ID);
    msg_join_resp->senderID(sender_ID);
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, false, pbkeyfile);

    EXPECT_TRUE(msg_join_resp->SignF(pvkeyfile));

    uint8_t* comparison_data;
    comparison_data = (uint8_t*) msg_join_resp->encrypted_data(false, pvkeyfile);
    EXPECT_EQ(*comparison_data, *encrypted_data);

    r_serial_data = msg_join_resp->Serialized();
    sz = msg_join_resp->SerializedLength();

    msg_join_resp2 = new SRUP_MSG_OBS_JOIN_RESP;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_join_resp2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_join_resp2->VerifyF(pbkeyfile));

    comparison_data = (uint8_t*) msg_join_resp2->encrypted_data(false, pvkeyfile);

    EXPECT_EQ(*comparison_data, *encrypted_data);

    delete(msg_join_resp2);
    delete(s_serial_data);
}

TEST_F(SRUP_OBS_JOIN_RESP_TESTS, Decrypt_Data_Test)
{
    msg_join_resp->token(token, token_length);
    msg_join_resp->sequenceID(sequence_ID);
    msg_join_resp->senderID(sender_ID);
    msg_join_resp->encrypted_data(encrypted_data, encrypted_data_length, true, pbkey);

    EXPECT_TRUE(msg_join_resp->Sign(pvkey));

    uint8_t* comparison_data;
    comparison_data = (uint8_t*) msg_join_resp->encrypted_data(true, pvkey);
    EXPECT_EQ(*comparison_data, *encrypted_data);

    r_serial_data = msg_join_resp->Serialized();
    sz = msg_join_resp->SerializedLength();

    msg_join_resp2 = new SRUP_MSG_OBS_JOIN_RESP;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_join_resp2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_join_resp2->Verify(pbkey));

    comparison_data = (uint8_t*) msg_join_resp2->encrypted_data(true, pvkey);

    EXPECT_EQ(*comparison_data, *encrypted_data);

    delete(msg_join_resp2);
    delete(s_serial_data);
}


// ********************************
// OBSERVE_REQ_TESTS
// ********************************

class SRUP_OBSERVE_REQ_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_OBSERVE_REQ *msg_obs_req;
    SRUP_MSG_OBSERVE_REQ *msg_obs_req2;

    uint8_t* token;
    uint16_t token_length;
    uint8_t* encrypted_data;
    uint16_t encrypted_data_length;

    char* pvkeyfile;
    char* pbkeyfile;

    char* pvkey;
    char* pbkey;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

protected:

    virtual void TearDown()
    {
        delete[] token;
        delete[] pvkeyfile;
        delete[] pbkeyfile;
        delete[] pvkey;
        delete[] pbkey;

        delete(sequence_ID);
        delete(sender_ID);
        delete[] encrypted_data;
        delete(msg_obs_req);
    }

    virtual void SetUp()
    {
        msg_obs_req = new SRUP_MSG_OBSERVE_REQ;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEYFILE)+1];
        std::strcpy(pvkeyfile, PVKEYFILE);

        pbkeyfile = new char[std::strlen(PBKEYFILE)+1];
        std::strcpy(pbkeyfile, PBKEYFILE);

        pvkey = new char[std::strlen(PVKEY)+1];
        std::strcpy(pvkey, PVKEY);

        pbkey = new char[std::strlen(PBKEY)+1];
        std::strcpy(pbkey, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 555ULL;

        encrypted_data = new uint8_t[16];

        encrypted_data[0x0] = 0x33;
        encrypted_data[0x1] = 0x44;
        encrypted_data[0x2] = 0x55;
        encrypted_data[0x3] = 0x66;
        encrypted_data[0x4] = 0x77;
        encrypted_data[0x5] = 0x88;
        encrypted_data[0x6] = 0x99;
        encrypted_data[0x7] = 0xAA;
        encrypted_data[0x8] = 0xBB;
        encrypted_data[0x9] = 0xCC;
        encrypted_data[0xA] = 0xDD;
        encrypted_data[0xB] = 0xEE;
        encrypted_data[0xC] = 0xFF;
        encrypted_data[0xD] = 0x00;
        encrypted_data[0xE] = 0x11;
        encrypted_data[0xF] = 0x22;

        encrypted_data_length = 16;
    }
};

TEST_F(SRUP_OBSERVE_REQ_TESTS, SignF_Blank_Message_Test)
{
    EXPECT_FALSE(msg_obs_req->SignF(pvkeyfile));
}

TEST_F(SRUP_OBSERVE_REQ_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_obs_req->Sign(pvkey));
}

TEST_F(SRUP_OBSERVE_REQ_TESTS, SignF_Complete_Message_Test)
{
    msg_obs_req->token(token, token_length);
    msg_obs_req->sequenceID(sequence_ID);
    msg_obs_req->senderID(sender_ID);
    msg_obs_req->encrypted_data(encrypted_data, encrypted_data_length, false, pbkeyfile);
    EXPECT_TRUE(msg_obs_req->SignF(pvkeyfile));
}

TEST_F(SRUP_OBSERVE_REQ_TESTS, Sign_Complete_Message_Test)
{
    msg_obs_req->token(token, token_length);
    msg_obs_req->sequenceID(sequence_ID);
    msg_obs_req->senderID(sender_ID);
    msg_obs_req->encrypted_data(encrypted_data, encrypted_data_length, true, pbkey);
    EXPECT_TRUE(msg_obs_req->Sign(pvkey));
}

TEST_F(SRUP_OBSERVE_REQ_TESTS, SignF_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_obs_req->SignF(pvkeyfile));
    msg_obs_req->token(token, token_length);
    EXPECT_FALSE(msg_obs_req->SignF(pvkeyfile));
    msg_obs_req->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_obs_req->SignF(pvkeyfile));
    msg_obs_req->senderID(sender_ID);
    EXPECT_FALSE(msg_obs_req->SignF(pvkeyfile));
    msg_obs_req->encrypted_data(encrypted_data, encrypted_data_length, false, pbkeyfile);
    EXPECT_TRUE(msg_obs_req->SignF(pvkeyfile));
}

TEST_F(SRUP_OBSERVE_REQ_TESTS, Sign_Incomplete_Message_Test)
{
    EXPECT_FALSE(msg_obs_req->Sign(pvkey));
    msg_obs_req->token(token, token_length);
    EXPECT_FALSE(msg_obs_req->Sign(pvkey));
    msg_obs_req->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_obs_req->Sign(pvkey));
    msg_obs_req->senderID(sender_ID);
    EXPECT_FALSE(msg_obs_req->Sign(pvkey));
    msg_obs_req->encrypted_data(encrypted_data, encrypted_data_length, true, pbkey);
    EXPECT_TRUE(msg_obs_req->Sign(pvkey));
}


TEST_F(SRUP_OBSERVE_REQ_TESTS, SignF_and_VerifyF_Message_Test)
{
    msg_obs_req->token(token, token_length);
    msg_obs_req->sequenceID(sequence_ID);
    msg_obs_req->senderID(sender_ID);
    msg_obs_req->encrypted_data(encrypted_data, encrypted_data_length, false, pbkeyfile);

    EXPECT_TRUE(msg_obs_req->SignF(pvkeyfile));
    EXPECT_TRUE(msg_obs_req->VerifyF(pbkeyfile));

    uint8_t msg_type;
    msg_type = *msg_obs_req->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_OBSERVE_REQ);

    r_serial_data = msg_obs_req->Serialized();
    sz = msg_obs_req->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*3); // 2-byte sizes for 3 variable-length fields
    expected_size+=token_length;
    expected_size+=316; // EncryptFed Data Length...

    EXPECT_EQ(sz, expected_size);

    msg_obs_req2 = new SRUP_MSG_OBSERVE_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_obs_req2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_obs_req2->VerifyF(pbkeyfile));

    char* recieved_token;
    recieved_token = (char*) msg_obs_req2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_obs_req2->token(token, token_length);

    recieved_token = (char*) msg_obs_req2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_obs_req2->VerifyF(pbkeyfile));

    delete(msg_obs_req2);
    delete(s_serial_data);
}

TEST_F(SRUP_OBSERVE_REQ_TESTS, Sign_and_Verify_Message_Test)
{
    msg_obs_req->token(token, token_length);
    msg_obs_req->sequenceID(sequence_ID);
    msg_obs_req->senderID(sender_ID);
    msg_obs_req->encrypted_data(encrypted_data, encrypted_data_length, true, pbkey);

    EXPECT_TRUE(msg_obs_req->Sign(pvkey));
    EXPECT_TRUE(msg_obs_req->Verify(pbkey));

    uint8_t msg_type;
    msg_type = *msg_obs_req->msgtype();
    EXPECT_EQ(msg_type, SRUP::SRUP_MESSAGE_TYPE_OBSERVE_REQ);

    r_serial_data = msg_obs_req->Serialized();
    sz = msg_obs_req->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*3); // 2-byte sizes for 3 variable-length fields
    expected_size+=token_length;
    expected_size+=316; // EncryptFed Data Length...

    EXPECT_EQ(sz, expected_size);

    msg_obs_req2 = new SRUP_MSG_OBSERVE_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_obs_req2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_obs_req2->Verify(pbkey));

    char* recieved_token;
    recieved_token = (char*) msg_obs_req2->token();

    EXPECT_STREQ(recieved_token, (char*) token);

    // Alter the token...
    token[0]=token[1];
    msg_obs_req2->token(token, token_length);

    recieved_token = (char*) msg_obs_req2->token();

    EXPECT_STRNE(recieved_token, (char*) TOKEN);
    EXPECT_FALSE(msg_obs_req2->Verify(pbkey));

    delete(msg_obs_req2);
    delete(s_serial_data);
}

TEST_F(SRUP_OBSERVE_REQ_TESTS, Generic_Deserialize_Test_F)
{
    msg_obs_req->token(token, token_length);
    msg_obs_req->sequenceID(sequence_ID);
    msg_obs_req->senderID(sender_ID);
    msg_obs_req->encrypted_data(encrypted_data, encrypted_data_length, false, pbkeyfile);

    EXPECT_TRUE(msg_obs_req->SignF(pvkeyfile));
    EXPECT_TRUE(msg_obs_req->VerifyF(pbkeyfile));

    r_serial_data = msg_obs_req->Serialized();
    sz = msg_obs_req->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*3); // 2-byte sizes for 3 variable-length fields
    expected_size+=token_length;
    expected_size+=316; // EncryptFed Data Length...

    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    delete(msg_generic);
    delete(s_serial_data);
}

TEST_F(SRUP_OBSERVE_REQ_TESTS, Generic_Deserialize_Test)
{
    msg_obs_req->token(token, token_length);
    msg_obs_req->sequenceID(sequence_ID);
    msg_obs_req->senderID(sender_ID);
    msg_obs_req->encrypted_data(encrypted_data, encrypted_data_length, true, pbkey);

    EXPECT_TRUE(msg_obs_req->Sign(pvkey));
    EXPECT_TRUE(msg_obs_req->Verify(pbkey));

    r_serial_data = msg_obs_req->Serialized();
    sz = msg_obs_req->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID
    expected_size+=(2*3); // 2-byte sizes for 3 variable-length fields
    expected_size+=token_length;
    expected_size+=316; // EncryptFed Data Length...

    EXPECT_EQ(sz, expected_size);

    auto msg_generic = new SRUP_MSG_GENERIC;

    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic->DeSerialize(s_serial_data));

    delete(msg_generic);
    delete(s_serial_data);
}

TEST_F(SRUP_OBSERVE_REQ_TESTS, DecryptF_Data_Test)
{
    msg_obs_req->token(token, token_length);
    msg_obs_req->sequenceID(sequence_ID);
    msg_obs_req->senderID(sender_ID);
    msg_obs_req->encrypted_data(encrypted_data, encrypted_data_length, false, pbkeyfile);

    EXPECT_TRUE(msg_obs_req->SignF(pvkeyfile));

    uint8_t* comparison_data;
    comparison_data = (uint8_t*) msg_obs_req->encrypted_data(false, pvkeyfile);
    EXPECT_EQ(*comparison_data, *encrypted_data);

    r_serial_data = msg_obs_req->Serialized();
    sz = msg_obs_req->SerializedLength();

    msg_obs_req2 = new SRUP_MSG_OBSERVE_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_obs_req2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_obs_req2->VerifyF(pbkeyfile));

    comparison_data = (uint8_t*) msg_obs_req2->encrypted_data(false, pvkeyfile);

    EXPECT_EQ(*comparison_data, *encrypted_data);

    delete(msg_obs_req2);
    delete(s_serial_data);
}

TEST_F(SRUP_OBSERVE_REQ_TESTS, Decrypt_Data_Test)
{
    msg_obs_req->token(token, token_length);
    msg_obs_req->sequenceID(sequence_ID);
    msg_obs_req->senderID(sender_ID);
    msg_obs_req->encrypted_data(encrypted_data, encrypted_data_length, true, pbkey);

    EXPECT_TRUE(msg_obs_req->Sign(pvkey));

    uint8_t* comparison_data;
    comparison_data = (uint8_t*) msg_obs_req->encrypted_data(true, pvkey);
    EXPECT_EQ(*comparison_data, *encrypted_data);

    r_serial_data = msg_obs_req->Serialized();
    sz = msg_obs_req->SerializedLength();

    msg_obs_req2 = new SRUP_MSG_OBSERVE_REQ;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_obs_req2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_obs_req2->Verify(pbkey));

    comparison_data = (uint8_t*) msg_obs_req2->encrypted_data(true, pvkey);

    EXPECT_EQ(*comparison_data, *encrypted_data);

    delete(msg_obs_req2);
    delete(s_serial_data);
}