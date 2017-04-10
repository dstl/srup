//
// Created by AJ Poulter on 18/07/2016.
//

#ifndef SRUP_SRUP_SERVER_H
#define SRUP_SRUP_SERVER_H

#include <mosquittopp.h>
#include <iostream>
#include <map>

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

class SRUP_Server : public mosqpp::mosquittopp
{
public:
    SRUP_Server (const char *id, const char *host, int port, int QOS = 0);
    ~SRUP_Server();

    // We can use this boolean if we ever need to signal to end the mqtt connection...
    bool mqtt_active;

    void on_message(const struct mosquitto_message *message);
    int disconnect();

    void add_topic(const char*);
    void do_subscribe();

    void set_public_key(const char*);
    void set_private_key(const char*);

    bool send_init_message(char*, char*, char*, char*);
    bool send_activate_message(char*);
    bool check_for_response(std::string);
    bool response_not_found(std::string);
    unsigned char get_response(std::string);

protected:
    int Response_Timeout;
    char* pvkeyfile;
    char* keyfile;
    std::list<std::string> topics_list;
    int QOS_Setting = 0;

    // We want a couple of maps (dictionaries) to store a list of the transactions that we've received a response from
    // Note that we need to use std::string rather than char* as the Thrift interface to Python uses std::string
    // And keeping everything as std::string (and converting to it where required) is easier than doing it the other way.
    std::map<std::string, unsigned char> response_list;
    std::map<std::string, int> not_found;

    // We also want another map to use as a list of open transactions... The map will keep the token and the target_ID
    // We'll add items when we send an INITIATE - and delete either when we send ACTIVATE ...
    // ...or if we get a RESPONSE that's not SRUP_UPDATE_SUCCESS (we can't activate a failed transation).

    std::map<std::string, std::string> transactions_list;

};

#endif //SRUP_SRUP_SERVER_H
