//
// Created by AJ Poulter on 27/04/2016.
//

#ifndef C2_TEST_SRUP_H
 #define C2_TEST_SRUP_H

#include "SRUP_Crypto.h"

#include <cstdint>
#include <cstring>
#include <cstdio>

#include <openssl/rsa.h>
#include <openssl/pem.h>

// We'll start with an abstract base-class
// The protocol elements common to all three message types are:
//  *   Version
//  *   Message Type
//  *   Signature
//  *   Token
//  *   Sequence ID  ==> New to version 0x02...
//  *   Sender ID    ==> New to version 0x03...
//
// So we'll include those in the base-class.
// Note that we need to treat the Sequence ID as a (long long) integer for comparisons – so we want a 64-bit unsigned int
// We can't assume that sizeof(unsigned long long int) will be 8-bytes (C99 specifies "at least 8-bytes") - so we
// must use a uint64_t... which of course means we have to include stdint.h (or cstdint as we're using C++)
// For the same reasons we're using uint8_t too instead of unsigned char's...
//
// Remember the library class doesn't (can't) do the sequence ID checking : this is a task for the device / server application.
//
// All of the classes will also need to be able to Serialize / Deserialize - so we'll include those methods too...
// ...but since they're specific to the fields that are in use: we'll declare those to be virtual in the base-class
// All of the derived classes will need to implement their own version of PreSign() and Sign() too.

namespace SRUP
{
    // Now we have added both the Sequence ID & Sender ID we have incremented the version to 0x03
    static const uint8_t SRUP_VERSION = 0x03;
}


class SRUP_MSG
{
public:
    SRUP_MSG();
    virtual ~SRUP_MSG();

    // C++11 only - but disable copy constructor & copy-assign constructor
    SRUP_MSG(const SRUP_MSG& that) = delete;
    void operator=(SRUP_MSG const &x) = delete;

    virtual uint8_t * Serialized()=0;
    virtual bool DeSerialize(const uint8_t *)=0;
    virtual uint32_t SerializedLength()=0;

    const uint8_t* version();
    const uint8_t* msgtype();

    const uint64_t* sequenceID();
    bool sequenceID(const uint64_t*);

    const uint64_t* senderID();
    bool senderID(const uint64_t*);

    uint8_t getByteVal(uint64_t, int);

    const uint8_t* signature();
    bool token(const uint8_t*, uint16_t);
    uint16_t token_lenght();
    const uint8_t* token();

    virtual bool Sign(char*);
    virtual bool Verify(char*);

protected:
    uint8_t * m_version;
    uint8_t * m_msgtype;
    uint64_t* m_sequence_ID;
    uint64_t* m_sender_ID;

    uint8_t* m_signature;
    uint16_t m_sig_len;

    uint8_t* m_token;
    uint16_t m_token_len;

    bool m_is_serialized;

    uint8_t * m_serialized;

    uint8_t * m_unsigned_message;

    uint32_t m_serial_length;
    uint32_t m_unsigned_length;

    uint16_t decodeLength(const uint8_t *);
    void encodeLength(uint8_t *, uint8_t *, uint16_t);

    virtual bool DataCheck()=0; // A virtual helper function for Sign()...
    virtual bool Serialize(bool optional = false)=0; // A virtual helper function for Serialized()...
};

#endif //C2_TEST_SRUP_H
