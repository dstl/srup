//
// Created by AJ Poulter on 11/08/2016.
//

#include <gtest/gtest.h>

#include <SRUP.h>
#include <SRUP_Init.h>
#include <SRUP_Response.h>
#include <SRUP_Activate.h>
#include <SRUP_Generic.h>

#include <cstring>

#define TARGET "TARGET"
#define TOKEN "TOKEN"
#define URL "http://www.google.com"
#define DIGEST "DIGEST"
#define PVKEY "private_key.pem"
#define PBKEY "public_key.pem"


class SRUP_INIT_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_INIT *msg_init;
    SRUP_MSG_INIT *msg_init2;

    char* target;
    char* token;
    char* url;
    char* digest;

    char* pvkeyfile;
    char* pbkeyfile;

    uint64_t* sequence_ID;

protected:

    virtual void TearDown()
    {
        delete(msg_init);
        delete(target);
        delete(token);
        delete(url);
        delete(digest);
        delete(pvkeyfile);
        delete(pbkeyfile);
        delete(sequence_ID);
    }

    virtual void SetUp()
    {
        msg_init = new SRUP_MSG_INIT;

        target = new char[std::strlen(TARGET)];
        std::strcpy(target, TARGET);

        token = new char[std::strlen(TOKEN)];
        std::strcpy(token, TOKEN);

        url = new char[std::strlen(URL)];
        std::strcpy(url, URL);

        digest = new char[std::strlen(DIGEST)];
        std::strcpy(digest, DIGEST);

        pvkeyfile = new char[std::strlen(PVKEY)];
        std::strcpy(pvkeyfile, PVKEY);

        pbkeyfile = new char[std::strlen(PBKEY)];
        std::strcpy(pbkeyfile, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;
    }

};


TEST_F(SRUP_INIT_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Set_Get_Sequence_ID)
{
    msg_init->sequenceID(sequence_ID);
    const uint64_t *sid = msg_init->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);
}

TEST_F(SRUP_INIT_TESTS, Serialize_Sequence_ID)
{
    msg_init->sequenceID(sequence_ID);
    msg_init->token(token);
    msg_init->target(target);
    msg_init->url(url);
    msg_init->digest(digest);

    msg_init->Sign(pvkeyfile);

    r_serial_data = msg_init->Serialized();
    sz = msg_init->SerializedLength();

    msg_init2 = new SRUP_MSG_INIT;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);
    msg_init2->DeSerialize(s_serial_data);
    const uint64_t* sid2 = msg_init2->sequenceID();
    EXPECT_TRUE(*sid2 == *sequence_ID);

}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_Test)
{
    msg_init->token(token);
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));

    msg_init->target(target);
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));

    msg_init->url(url);
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_Token_Only_Test)
{
    msg_init->token(token);
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_Target_Only_Test)
{
    msg_init->target(target);
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_url_Only_Test)
{
    msg_init->url(url);
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_Digest_Only_Test)
{
    msg_init->digest(digest);
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Complete_Message_Test)
{
    msg_init->token(token);
    msg_init->target(target);
    msg_init->url(url);
    msg_init->digest(digest);

    EXPECT_TRUE(msg_init->Sign(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_and_Verify_Message_Test)
{
    msg_init->token(token);
    msg_init->target(target);
    msg_init->url(url);
    msg_init->digest(digest);
    msg_init->sequenceID(sequence_ID);

    EXPECT_TRUE(msg_init->Sign(pvkeyfile));

    r_serial_data = msg_init->Serialized();
    sz = msg_init->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=(2*5); // 2-byte sizes for 5 variable-length fields
    expected_size+=std::strlen(token);
    expected_size+=std::strlen(target);
    expected_size+=std::strlen(url);
    expected_size+=std::strlen(digest);

    EXPECT_EQ(sz, expected_size);

    msg_init2 = new SRUP_MSG_INIT;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_init2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_init2->Verify(pbkeyfile));

    msg_init2->target(token);
    EXPECT_FALSE(msg_init2->Verify(pbkeyfile));

    delete(msg_init2);
    delete(s_serial_data);
}


TEST_F(SRUP_INIT_TESTS, Sign_and_Verify_Long_Message_Test)
{
    // Test 65535-byte strings for fields.
    const int length = 65535;

    char test[length + 1];
    std::memset(test, 0, length + 1);
    std::memset(test, '.', length);

    EXPECT_EQ(length, std::strlen(test));

    msg_init->token(test);
    msg_init->target(test);
    msg_init->url(test);
    msg_init->digest(test);
    msg_init->sequenceID(sequence_ID);

    EXPECT_TRUE(msg_init->Sign(pvkeyfile));

    r_serial_data = msg_init->Serialized();
    sz = msg_init->SerializedLength();
    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequenceID
    expected_size+=(2*5); // 2-byte sizes for 5 variable-length fields
    expected_size+=(4*length);

    EXPECT_EQ(sz, expected_size);

    msg_init2 = new SRUP_MSG_INIT;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_init2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_init2->Verify(pbkeyfile));

    EXPECT_STREQ(msg_init2->url(), test);

    msg_init2->target(token);
    EXPECT_FALSE(msg_init2->Verify(pbkeyfile));

    delete(msg_init2);
    delete(s_serial_data);
}

class SRUP_RESP_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_RESPONSE *msg_resp;
    SRUP_MSG_RESPONSE *msg_resp2;

    char* token;

    char* pvkeyfile;
    char* pbkeyfile;

    uint64_t* sequence_ID;

protected:

    virtual void TearDown()
    {
        delete(token);
        delete(pvkeyfile);
        delete(pbkeyfile);
        delete(sequence_ID);
    }

    virtual void SetUp()
    {
        msg_resp = new SRUP_MSG_RESPONSE;

        token = new char[std::strlen(TOKEN)];
        std::strcpy(token, TOKEN);

        pvkeyfile = new char[std::strlen(PVKEY)];
        std::strcpy(pvkeyfile, PVKEY);

        pbkeyfile = new char[std::strlen(PBKEY)];
        std::strcpy(pbkeyfile, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;
    }

};

TEST_F(SRUP_RESP_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_resp->Sign(pvkeyfile));
}

TEST_F(SRUP_RESP_TESTS, Sign_Incomplete_Message_Test)
{
    msg_resp->token(token);
    EXPECT_FALSE(msg_resp->Sign(pvkeyfile));
}

TEST_F(SRUP_RESP_TESTS, Sign_Complete_Message_Test)
{
    msg_resp->token(token);
    msg_resp->sequenceID(sequence_ID);
    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_SUCCESS);
    EXPECT_TRUE(msg_resp->Sign(pvkeyfile));

    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_FAIL_SERVER);
    EXPECT_TRUE(msg_resp->Sign(pvkeyfile));

    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_FAIL_FILE);
    EXPECT_TRUE(msg_resp->Sign(pvkeyfile));

    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_FAIL_DIGEST);
    EXPECT_TRUE(msg_resp->Sign(pvkeyfile));
}

TEST_F(SRUP_RESP_TESTS, Sign_and_Verify_Message_Test)
{
    msg_resp->token(token);
    msg_resp->sequenceID(sequence_ID);
    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_SUCCESS);

    EXPECT_TRUE(msg_resp->Sign(pvkeyfile));

    r_serial_data = msg_resp->Serialized();
    sz = msg_resp->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=1; // status
    expected_size+=std::strlen(token);

    EXPECT_EQ(sz, expected_size);

    msg_resp2 = new SRUP_MSG_RESPONSE;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_resp2->DeSerialize(s_serial_data));
    const uint64_t* sid = msg_resp2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);
    EXPECT_TRUE(msg_resp2->Verify(pbkeyfile));

    // Alter the token...
    token[0]=token[1];

    msg_resp2->token(token);
    EXPECT_FALSE(msg_resp2->Verify(pbkeyfile));

    delete(msg_resp2);
    delete(s_serial_data);
}

class SRUP_ACTIVATE_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_ACTIVATE *msg_activate;
    SRUP_MSG_ACTIVATE *msg_activate2;

    char* token;

    char* pvkeyfile;
    char* pbkeyfile;

    uint64_t* sequence_ID;

protected:

    virtual void TearDown()
    {
        delete(token);
        delete(pvkeyfile);
        delete(pbkeyfile);
        delete(sequence_ID);
    }

    virtual void SetUp()
    {
        msg_activate = new SRUP_MSG_ACTIVATE;

        token = new char[std::strlen(TOKEN)];
        std::strcpy(token, TOKEN);

        pvkeyfile = new char[std::strlen(PVKEY)];
        std::strcpy(pvkeyfile, PVKEY);

        pbkeyfile = new char[std::strlen(PBKEY)];
        std::strcpy(pbkeyfile, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

    }

};

TEST_F(SRUP_ACTIVATE_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_activate->Sign(pvkeyfile));
}

TEST_F(SRUP_ACTIVATE_TESTS, Sign_Complete_Message_Test)
{
    msg_activate->token(token);
    msg_activate->sequenceID(sequence_ID);
    EXPECT_TRUE(msg_activate->Sign(pvkeyfile));
}

TEST_F(SRUP_ACTIVATE_TESTS, Sign_and_Verify_Message_Test)
{
    msg_activate->token(token);
    msg_activate->sequenceID(sequence_ID);

    EXPECT_TRUE(msg_activate->Sign(pvkeyfile));

    r_serial_data = msg_activate->Serialized();
    sz = msg_activate->SerializedLength();

    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=(2*2); // 2-byte sizes for 2 variable-length fields
    expected_size+=std::strlen(token);

    EXPECT_EQ(sz, expected_size);

    msg_activate2 = new SRUP_MSG_ACTIVATE;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_activate2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_activate2->Verify(pbkeyfile));

    // Alter the token...
    token[0]=token[1];

    msg_activate2->token(token);
    EXPECT_FALSE(msg_activate2->Verify(pbkeyfile));

    delete(msg_activate2);
    delete(s_serial_data);
}


class SRUP_GENERIC_TESTS : public ::testing::Test
{
public:

    SRUP_MSG_GENERIC *msg_generic;
    SRUP_MSG_GENERIC *msg_generic2;

    char* pvkeyfile;
    char* pbkeyfile;
    uint64_t* sequence_ID;

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;

    size_t sz;

protected:

    virtual void TearDown()
    {
        delete(pvkeyfile);
        delete(pbkeyfile);
        delete(sequence_ID);
    }

    virtual void SetUp()
    {
        msg_generic = new SRUP_MSG_GENERIC;

        pvkeyfile = new char[std::strlen(PVKEY)];
        std::strcpy(pvkeyfile, PVKEY);

        pbkeyfile = new char[std::strlen(PBKEY)];
        std::strcpy(pbkeyfile, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;
    }

};

TEST_F(SRUP_GENERIC_TESTS, MessageTypeAndSeqIDTest)
{
    char *x = msg_generic->msgtype();
    EXPECT_TRUE(*x == SRUP::SRUP_MESSAGE_TYPE_GENERIC);

    msg_generic->sequenceID(sequence_ID);
    r_serial_data=msg_generic->Serialized();
    sz = msg_generic->SerializedLength();

    int expected_size=0;

    expected_size+=2; // header
    expected_size+=8; // sequence_ID

    EXPECT_EQ(sz, expected_size);

    msg_generic2 = new SRUP_MSG_GENERIC;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic2->DeSerialize(s_serial_data));

    const uint64_t* sid = msg_generic2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);
}

TEST_F(SRUP_GENERIC_TESTS, Sign_Generic_Message_Test)
{
    EXPECT_FALSE(msg_generic->Sign(pvkeyfile));
}

TEST_F(SRUP_GENERIC_TESTS, Verify_Generic_Message_Test)
{
    EXPECT_FALSE(msg_generic->Verify(pbkeyfile));
}
