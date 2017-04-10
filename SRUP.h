//
// Created by AJ Poulter on 27/04/2016.
//

#ifndef C2_TEST_SRUP_H
 #define C2_TEST_SRUP_H

#include "SRUP_Crypto.h"

#include <stdint.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

// We'll start with an abstract base-class
// The protocol elements common to all three message types are:
//  *   Version
//  *   Message Type
//  *   Signature
//  *   Token
//  *   Sequence ID  ==> New to version 0x02...
//
// So we'll include those in the base-class.
// Note that we need to treat teh Sequence ID as an int for comparisons – so we want a 64-bit unsigned int
// We can't assume that sizeof(unsigned long long int) will be 8-bytes (C99 specifies "at least 8-bytes") - so we
// must use a uint64_t... which of course means we have to include stdint.h
// Given assumptions about other lengths we should probably be using uint8_t etc too...
// TODO: Look at replacing types with fixed sizes...
//
// All of the classes will also need to be able to Serialize / Deserialize - so we'll include those methods too...
// ...but since they're specific to the fields that are in use: we'll declare those to be virtual in the base-class
// All of the derived classes will need to implement their own version of PreSign() and Sign() too.

namespace SRUP
{
    static const unsigned char SRUP_VERSION = 0x02;
}


class SRUP_MSG
{
public:
    SRUP_MSG();
    virtual ~SRUP_MSG();

    // C++11 only - but disable copy constructor & copy-assign constructor
    SRUP_MSG(const SRUP_MSG& that) = delete;
    void operator=(SRUP_MSG const &x) = delete;

    virtual unsigned char* Serialized()=0;
    virtual bool DeSerialize(const unsigned char*)=0;
    virtual size_t SerializedLength()=0;

    char* version();
    char* msgtype();

    const uint64_t* sequenceID();
    bool sequenceID(const uint64_t*);

    uint8_t getByteVal(uint64_t, int);

    unsigned char* signature();
    bool token(const char*);
    const char* token();

    virtual bool Sign(char*);
    virtual bool Verify(char*);

protected:
    char* m_version;
    char* m_msgtype;
    uint64_t* m_sequence_ID;

    unsigned char* m_signature;
    unsigned int m_sig_len;
    char* m_token;
    bool m_is_serialized;

    unsigned char* m_serialized;

    unsigned char* m_unsigned_message;

    size_t m_serial_length;
    size_t m_unsigned_length;

    unsigned short decodeLength(const unsigned char*);
    void encodeLength(unsigned char*, unsigned char*, size_t);

    virtual bool DataCheck()=0; // A virtual helper function for Sign()...
    virtual bool Serialize(bool optional = false)=0; // A virtual helper function for Serialized()...
};

#endif //C2_TEST_SRUP_H
