//
// Created by AJ Poulter on 18/07/2016.
//

#ifndef SRUP_SRUP_DAEMON_H
#define SRUP_SRUP_DAEMON_H

#include <mosquittopp.h>
#include <iostream>

#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/support/date_time.hpp>

#include <SRUP.h>
#include <SRUP_Init.h>
#include <SRUP_Response.h>
#include <SRUP_Activate.h>
#include <SRUP_Generic.h>

#define MAX_PAYLOAD 65535
#define DEFAULT_KEEP_ALIVE 60

class SRUP_Daemon : public mosqpp::mosquittopp
{
public:
    SRUP_Daemon (const char *id, const char *host, int port);
    ~SRUP_Daemon();
    bool done;

    void listen_topic(char*);
    char* listen_topic();

    void on_message(const struct mosquitto_message *message);
    void on_connect(int);
    int disconnect();

    void set_public_key(const char*);
    void set_private_key(const char*);

protected:
    char* listentopic;
    char* pvkeyfile;
    char* keyfile;
    uint64_t seqid;
    uint64_t rec_seqid;

    void on_SRUP_Activate_message(SRUP_MSG_ACTIVATE*);
    void on_SRUP_Init_message(SRUP_MSG_INIT*);
};

#endif //SRUP_SRUP_DAEMON_H
