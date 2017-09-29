//
// Created by AJ Poulter on 11/08/2016.
//

#include <gtest/gtest.h>

#include <SRUP.h>
#include <SRUP_Init.h>
#include <SRUP_Response.h>
#include <SRUP_Activate.h>
#include <SRUP_Generic.h>
#include <SRUP_Action.h>
#include <SRUP_Data.h>

#include <cstring>

#define TARGET "TARGET"
#define TOKEN "TOKEN"
#define URL "http://www.google.com"
#define DIGEST "DIGEST"
#define PVKEY "private_key.pem"
#define PBKEY "public_key.pem"
#define DATA_ID "My_Data_ID"
#define DATA1 "Test Data"
#define DATA2 256
#define DATA3 128.26


class SRUP_INIT_TESTS : public ::testing::Test
{
public:

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;
    size_t sz;

    SRUP_MSG_INIT *msg_init;
    SRUP_MSG_INIT *msg_init2;

    uint8_t * target;
    uint8_t * token;
    char* url;
    uint8_t * digest;

    uint16_t target_length;
    uint16_t token_length;
    uint16_t digest_length;

    char* pvkeyfile;
    char* pbkeyfile;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

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
        delete(sender_ID);
    }

    virtual void SetUp()
    {
        msg_init = new SRUP_MSG_INIT;

        target_length = std::strlen(TARGET);
        target = new uint8_t[target_length];
        std::memcpy(target, TARGET, target_length);

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        url = new char[std::strlen(URL)];
        std::strcpy(url, URL);

        digest_length = std::strlen(DIGEST);
        digest = new uint8_t[digest_length];
        std::memcpy(digest, DIGEST, digest_length);

        pvkeyfile = new char[std::strlen(PVKEY)];
        std::strcpy(pvkeyfile, PVKEY);

        pbkeyfile = new char[std::strlen(PBKEY)];
        std::strcpy(pbkeyfile, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 55ULL;
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

TEST_F(SRUP_INIT_TESTS, Set_Get_Sender_ID)
{
    msg_init->senderID(sender_ID);
    const uint64_t *snd = msg_init->senderID();
    EXPECT_TRUE(*snd == *sender_ID);
}

TEST_F(SRUP_INIT_TESTS, Serialize_Sequence_ID)
{
    msg_init->sequenceID(sequence_ID);
    msg_init->token(token, token_length);
    msg_init->target(target, target_length);
    msg_init->url(url);
    msg_init->digest(digest, digest_length);
    msg_init->senderID(sender_ID);

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

TEST_F(SRUP_INIT_TESTS, Serialize_Sender_ID)
{
    msg_init->sequenceID(sequence_ID);
    msg_init->token(token, token_length);
    msg_init->target(target, target_length);
    msg_init->url(url);
    msg_init->digest(digest, digest_length);
    msg_init->senderID(sender_ID);

    msg_init->Sign(pvkeyfile);

    r_serial_data = msg_init->Serialized();
    sz = msg_init->SerializedLength();

    msg_init2 = new SRUP_MSG_INIT;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);
    msg_init2->DeSerialize(s_serial_data);
    const uint64_t* snd2 = msg_init2->senderID();
    EXPECT_TRUE(*snd2 == *sender_ID);
    delete (msg_init2);
    delete(s_serial_data);

}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_Test)
{
    msg_init->token(token, token_length);
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));

    msg_init->target(target, target_length);
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));

    msg_init->url(url);
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));

    msg_init->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_Token_Only_Test)
{
    msg_init->token(token, token_length);
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_Target_Only_Test)
{
    msg_init->target(target, target_length);
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_url_Only_Test)
{
    msg_init->url(url);
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_Digest_Only_Test)
{
    msg_init->digest(digest, digest_length);
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_Sequence_Only_Test)
{
    msg_init->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Incomplete_Message_Sender_Only_Test)
{
    msg_init->senderID(sender_ID);
    EXPECT_FALSE(msg_init->Sign(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_Complete_Message_Test)
{
    msg_init->token(token, token_length);
    msg_init->target(target, target_length);
    msg_init->url(url);
    msg_init->digest(digest, digest_length);
    msg_init->senderID(sender_ID);
    msg_init->sequenceID(sequence_ID);

    EXPECT_TRUE(msg_init->Sign(pvkeyfile));
}

TEST_F(SRUP_INIT_TESTS, Sign_and_Verify_Message_Test)
{
    msg_init->token(token, token_length);
    msg_init->target(target, target_length);
    msg_init->url(url);
    msg_init->digest(digest, digest_length);
    msg_init->sequenceID(sequence_ID);
    msg_init->senderID(sender_ID);

    EXPECT_TRUE(msg_init->Sign(pvkeyfile));
    EXPECT_TRUE(msg_init->Verify(pbkeyfile));

    r_serial_data = msg_init->Serialized();
    sz = msg_init->SerializedLength();

    uint32_t expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequence ID
    expected_size+=8; // sender ID
    expected_size+=(2*5); // 2-byte sizes for 5 variable-length fields
    expected_size+=token_length;
    expected_size+=target_length;
    expected_size+=std::strlen(url);
    expected_size+=digest_length;

    EXPECT_EQ(sz, expected_size);

    msg_init2 = new SRUP_MSG_INIT;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_init2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_init2->Verify(pbkeyfile));

    msg_init2->target(token, token_length);
    EXPECT_FALSE(msg_init2->Verify(pbkeyfile));

    delete(msg_init2);
    delete(s_serial_data);
}


TEST_F(SRUP_INIT_TESTS, Sign_and_Verify_Long_Message_Test)
{
    // Test 65535-byte strings for fields.
    const int length = 65535;

    uint8_t test[length];
    std::memset(test, 0xFF, length);

    char url[length + 1];
    std::memset(url, 'x', length);
    url[length]=0;

    msg_init->token(test, length);
    msg_init->target(test, length);
    msg_init->url(url);
    msg_init->digest(test, length);
    msg_init->sequenceID(sequence_ID);
    msg_init->senderID(sender_ID);

    EXPECT_TRUE(msg_init->Sign(pvkeyfile));

    r_serial_data = msg_init->Serialized();
    sz = msg_init->SerializedLength();
    int expected_size=0;

    expected_size+=256; // expected signature length
    expected_size+=2; // header
    expected_size+=8; // sequenceID
    expected_size+=8; // senderID
    expected_size+=(2*5); // 2-byte sizes for 5 variable-length fields
    expected_size+=(4*length);

    EXPECT_EQ(sz, expected_size);

    msg_init2 = new SRUP_MSG_INIT;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_init2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_init2->Verify(pbkeyfile));

    EXPECT_STREQ(msg_init2->url(), url);

    msg_init2->target(token, length);
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

    uint8_t * token;
    uint16_t token_length;

    char* pvkeyfile;
    char* pbkeyfile;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

protected:

    virtual void TearDown()
    {
        delete(token);
        delete(pvkeyfile);
        delete(pbkeyfile);
        delete(sequence_ID);
        delete(sender_ID);
    }

    virtual void SetUp()
    {
        msg_resp = new SRUP_MSG_RESPONSE;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEY)];
        std::strcpy(pvkeyfile, PVKEY);

        pbkeyfile = new char[std::strlen(PBKEY)];
        std::strcpy(pbkeyfile, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 55ULL;
    }

};

TEST_F(SRUP_RESP_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_resp->Sign(pvkeyfile));
}

TEST_F(SRUP_RESP_TESTS, Sign_Incomplete_Message_Test)
{
    msg_resp->token(token, token_length);
    EXPECT_FALSE(msg_resp->Sign(pvkeyfile));
}

TEST_F(SRUP_RESP_TESTS, Sign_Complete_Message_Test)
{
    msg_resp->token(token, token_length);
    msg_resp->sequenceID(sequence_ID);
    msg_resp->senderID(sender_ID);
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
    msg_resp->token(token, token_length);
    msg_resp->sequenceID(sequence_ID);
    msg_resp->senderID(sender_ID);
    msg_resp->status(SRUP::UPDATE::SRUP_UPDATE_SUCCESS);

    EXPECT_TRUE(msg_resp->Sign(pvkeyfile));

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

    EXPECT_TRUE(msg_resp2->Verify(pbkeyfile));

    // Alter the token...
    token[0]=token[1];

    msg_resp2->token(token, token_length);
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

    uint8_t* token;
    uint16_t token_length;

    char* pvkeyfile;
    char* pbkeyfile;

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

protected:

    virtual void TearDown()
    {
        delete(token);
        delete(pvkeyfile);
        delete(pbkeyfile);
        delete(sequence_ID);
        delete(sender_ID);
    }

    virtual void SetUp()
    {
        msg_activate = new SRUP_MSG_ACTIVATE;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEY)];
        std::strcpy(pvkeyfile, PVKEY);

        pbkeyfile = new char[std::strlen(PBKEY)];
        std::strcpy(pbkeyfile, PBKEY);

        sequence_ID = new uint64_t;
        *sequence_ID = 1ULL;

        sender_ID = new uint64_t;
        *sender_ID = 555ULL;

    }

};

TEST_F(SRUP_ACTIVATE_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_activate->Sign(pvkeyfile));
}

TEST_F(SRUP_ACTIVATE_TESTS, Sign_Complete_Message_Test)
{
    msg_activate->token(token, token_length);
    msg_activate->sequenceID(sequence_ID);
    msg_activate->senderID(sender_ID);
    EXPECT_TRUE(msg_activate->Sign(pvkeyfile));
}

TEST_F(SRUP_ACTIVATE_TESTS, Sign_and_Verify_Message_Test)
{
    msg_activate->token(token, token_length);
    msg_activate->sequenceID(sequence_ID);
    msg_activate->senderID(sender_ID);

    EXPECT_TRUE(msg_activate->Sign(pvkeyfile));

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
    EXPECT_TRUE(msg_activate2->Verify(pbkeyfile));

    // Alter the token...
    token[0]=token[1];

    msg_activate2->token(token, token_length);
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
    uint64_t* sender_ID;

    unsigned char* r_serial_data;
    unsigned char* s_serial_data;

    size_t sz;

protected:

    virtual void TearDown()
    {
        delete(pvkeyfile);
        delete(pbkeyfile);
        delete(sequence_ID);
        delete(sender_ID);
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

        sender_ID = new uint64_t;
        *sender_ID = 7777ULL;
    }

};

TEST_F(SRUP_GENERIC_TESTS, MessageTypeSenderAndSeqIDTest)
{
    const uint8_t *x = msg_generic->msgtype();
    EXPECT_TRUE(*x == SRUP::SRUP_MESSAGE_TYPE_GENERIC);

    msg_generic->sequenceID(sequence_ID);
    msg_generic->senderID(sender_ID);
    r_serial_data=msg_generic->Serialized();
    sz = msg_generic->SerializedLength();

    int expected_size=0;

    expected_size+=2; // header
    expected_size+=8; // sequence_ID
    expected_size+=8; // sender_ID

    EXPECT_EQ(sz, expected_size);

    msg_generic2 = new SRUP_MSG_GENERIC;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_generic2->DeSerialize(s_serial_data));

    const uint64_t* sid = msg_generic2->sequenceID();
    EXPECT_TRUE(*sid == *sequence_ID);

    const uint64_t* snd = msg_generic2->sequenceID();
    EXPECT_TRUE(*snd == *sequence_ID);
}

TEST_F(SRUP_GENERIC_TESTS, Sign_Generic_Message_Test)
{
    // By definition we cannot sign a generic message...
    EXPECT_FALSE(msg_generic->Sign(pvkeyfile));
}

TEST_F(SRUP_GENERIC_TESTS, Verify_Generic_Message_Test)
{
    // ...and correspondingly we can't verify one either.
    EXPECT_FALSE(msg_generic->Verify(pbkeyfile));
}



class SRUP_ACTION_TESTS : public ::testing::Test
{
public:

    SRUP_MSG_ACTION *msg_action;
    SRUP_MSG_ACTION *msg_action2;

    char* pvkeyfile;
    char* pbkeyfile;

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
        delete(pvkeyfile);
        delete(pbkeyfile);
        delete(sequence_ID);
        delete(action);
        delete(action2);
        delete(token);
        delete(sender_ID);
    }

    virtual void SetUp()
    {
        msg_action = new SRUP_MSG_ACTION;

        pvkeyfile = new char[std::strlen(PVKEY)];
        std::strcpy(pvkeyfile, PVKEY);

        pbkeyfile = new char[std::strlen(PBKEY)];
        std::strcpy(pbkeyfile, PBKEY);

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

TEST_F(SRUP_ACTION_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_action->Sign(pvkeyfile));
}

TEST_F(SRUP_ACTION_TESTS, Sign_Incomplete_Message_Test)
{
    msg_action->token(token, token_length);
    EXPECT_FALSE(msg_action->Sign(pvkeyfile));
    msg_action->action_ID(action);
    EXPECT_FALSE(msg_action->Sign(pvkeyfile));
    msg_action->senderID(sender_ID);
    EXPECT_FALSE(msg_action->Sign(pvkeyfile));
}

TEST_F(SRUP_ACTION_TESTS, Sign_Complete_Message_Test)
{
    msg_action->token(token, token_length);
    msg_action->sequenceID(sequence_ID);
    msg_action->action_ID(action);
    msg_action->senderID(sender_ID);
    EXPECT_TRUE(msg_action->Sign(pvkeyfile));
}

TEST_F(SRUP_ACTION_TESTS, TestActions)
{
    msg_action->action_ID(action);
    EXPECT_TRUE(*msg_action->action_ID() == *action);
    msg_action->action_ID(action2);
    EXPECT_FALSE(*msg_action->action_ID() == *action);
}

TEST_F(SRUP_ACTION_TESTS, Sign_and_Verify_Message_Test)
{
    msg_action->token(token, token_length);
    msg_action->sequenceID(sequence_ID);
    msg_action->senderID(sender_ID);
    msg_action->action_ID(action);

    EXPECT_TRUE(msg_action->Sign(pvkeyfile));

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

    EXPECT_TRUE(msg_action2->Verify(pbkeyfile));
    EXPECT_TRUE(*msg_action2->action_ID() == *action);

    // Alter the token...
    token[0]=token[1];

    msg_action2->token(token, token_length);
    EXPECT_FALSE(msg_action2->Verify(pbkeyfile));

    delete(msg_action2);
    delete(s_serial_data);
}

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

    uint64_t* sequence_ID;
    uint64_t* sender_ID;

protected:

    virtual void TearDown()
    {
        delete(token);
        delete(pvkeyfile);
        delete(pbkeyfile);
        delete(sequence_ID);
        delete(sender_ID);
        delete(data);
        delete(data_ID);
    }

    virtual void SetUp()
    {
        msg_data = new SRUP_MSG_DATA;

        token_length = std::strlen(TOKEN);
        token = new uint8_t[token_length];
        std::memcpy(token, TOKEN, token_length);

        pvkeyfile = new char[std::strlen(PVKEY)];
        std::strcpy(pvkeyfile, PVKEY);

        pbkeyfile = new char[std::strlen(PBKEY)];
        std::strcpy(pbkeyfile, PBKEY);

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

TEST_F(SRUP_DATA_TESTS, Sign_Blank_Message_Test)
{
    EXPECT_FALSE(msg_data->Sign(pvkeyfile));
}

TEST_F(SRUP_DATA_TESTS, Sign_Incomplete_Message_Test)
{
    msg_data->token(token, token_length);
    EXPECT_FALSE(msg_data->Sign(pvkeyfile));
    msg_data->data_ID(data_ID, data_ID_length);
    EXPECT_FALSE(msg_data->Sign(pvkeyfile));
    msg_data->data(data, data_length);
    EXPECT_FALSE(msg_data->Sign(pvkeyfile));
    msg_data->sequenceID(sequence_ID);
    EXPECT_FALSE(msg_data->Sign(pvkeyfile));
}

TEST_F(SRUP_DATA_TESTS, Sign_Complete_Message_Test)
{
    msg_data->token(token, token_length);
    msg_data->sequenceID(sequence_ID);
    msg_data->data_ID(data_ID, data_ID_length);
    msg_data->senderID(sender_ID);
    msg_data->data(data, data_length);
    EXPECT_TRUE(msg_data->Sign(pvkeyfile));
}

TEST_F(SRUP_DATA_TESTS, TestDataTypes)
{
    msg_data->data(data, data_length);
    EXPECT_TRUE(*msg_data->data() == *data);
    msg_data->data(data2);
    EXPECT_FALSE(*msg_data->data() == *data);
    EXPECT_TRUE(msg_data->data_uint32() == data2);
    msg_data->data(data3);
    EXPECT_FALSE(*msg_data->data() == *data);
    EXPECT_TRUE(msg_data->data_double() == data3);
}

TEST_F(SRUP_DATA_TESTS, Sign_and_Verify_Message_Test)
{
    msg_data->token(token, token_length);
    msg_data->sequenceID(sequence_ID);
    msg_data->senderID(sender_ID);
    msg_data->data_ID(data_ID, data_ID_length);
    msg_data->data(data, data_length);

    EXPECT_TRUE(msg_data->Sign(pvkeyfile));
    EXPECT_TRUE(msg_data->Verify(pbkeyfile));

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

    EXPECT_TRUE(msg_data2->Verify(pbkeyfile));

    // Alter the token...
    token[0]=token[1];

    msg_data2->token(token, token_length);
    EXPECT_FALSE(msg_data2->Verify(pbkeyfile));

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

    msg_data->Sign(pvkeyfile);

    r_serial_data = msg_data->Serialized();
    sz = msg_data->SerializedLength();

    msg_data2 = new SRUP_MSG_DATA;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);

    EXPECT_TRUE(msg_data2->DeSerialize(s_serial_data));
    EXPECT_TRUE(*msg_data2->data() == *data);

    delete(msg_data2);

    msg_data->data(data2);
    msg_data->Sign(pvkeyfile);
    r_serial_data = msg_data->Serialized();
    sz = msg_data->SerializedLength();
    msg_data2 = new SRUP_MSG_DATA;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);
    EXPECT_TRUE(msg_data2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_data2->data_uint32() == data2);

    delete(msg_data2);

    msg_data->data(data3);
    msg_data->Sign(pvkeyfile);
    r_serial_data = msg_data->Serialized();
    sz = msg_data->SerializedLength();
    msg_data2 = new SRUP_MSG_DATA;
    s_serial_data = new unsigned char[sz];
    std::memcpy(s_serial_data, r_serial_data, sz);
    EXPECT_TRUE(msg_data2->DeSerialize(s_serial_data));
    EXPECT_TRUE(msg_data2->data_double() == data3);

    delete(msg_data2);
    delete(s_serial_data);
}