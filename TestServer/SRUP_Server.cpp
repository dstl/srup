//
// Created by AJ Poulter on 18/07/2016.
//

// We will want to be subscribed to a number of different MQTT topics pertaining to a number of differnt devices...
// In a full implementation we'd store these somewhere (e.g. a database) and load them when we start the server.

#include "SRUP_Server.h"
#include <thread>
#include <chrono>

SRUP_Server::SRUP_Server(const char *id, const char *host, int port, int QOS) : mosquittopp(id)
{
    mqtt_active = true;
    seqid = 0;
    rec_seqid = 0;

    Response_Timeout = 4 * 60; // SRUP RESPONSE timeout - 60 seconds.

    keyfile = NULL;
    pvkeyfile = NULL;

    int keepalive = DEFAULT_KEEP_ALIVE;
    connect(host, port, keepalive);
    QOS_Setting = QOS;
}

void SRUP_Server::on_message(const struct mosquitto_message *message)
{
    unsigned char buf[MAX_PAYLOAD];

    // Here we need to define an object for any message type that we could receive from an external sender...
    // ...plus the generic message which we use to determine the type of the message we have received.
    // Since this server only implements INITIATE, RESPONSE & ACTIVATE - the only message type we're expecting
    // to receive is a SRUP_MSG_RESPONSE...

    SRUP_MSG_GENERIC *msg_generic;
    SRUP_MSG_RESPONSE *msg_response;

    char msgtype;

    msg_generic = new(SRUP_MSG_GENERIC);

    std::memset(buf, 0, MAX_PAYLOAD * sizeof(char));
    std::memcpy(buf, message->payload, MAX_PAYLOAD * sizeof(char));

    if (msg_generic->DeSerialize(buf))
    {
        if (*msg_generic->version() == SRUP::SRUP_VERSION)
        {
            msgtype = *msg_generic->msgtype();

            if (msgtype == SRUP::SRUP_MESSAGE_TYPE_RESPONSE)
            {
                msg_response = new(SRUP_MSG_RESPONSE);
                msg_response->DeSerialize(buf);

                if ((keyfile == NULL) || (pvkeyfile == NULL))
                {
                    BOOST_LOG_TRIVIAL(error) << "Certificate keyfiles not set";
                }
                else
                {
                    if (msg_response->Verify(keyfile))
                    {
                        BOOST_LOG_TRIVIAL(info) << "Message Type: SRUP_MESSAGE_TYPE_RESPONSE";
                        BOOST_LOG_TRIVIAL(info) << "Token: " << msg_response->token();
                        uint64_t rsid;
                        rsid = *msg_response->sequenceID();
                        if (rsid < rec_seqid)
                        {
                            // We have received an invalid sequenceID... so this is probably a replay attack...
                            // So we should ignore this message - and log the details...
                            BOOST_LOG_TRIVIAL(warning) << "SRUP_MESSAGE_TYPE_RESPONSE message has invalid Sequence ID "
                                                       << rsid << " Expected > " << rec_seqid;
                            delete(msg_response);
                            return;
                        }
                        else
                        {
                            std::string tkn(msg_response->token());
                            unsigned char sts = *msg_response->status();

                            // To be extra defensive we could also check to see if the token is in the list before adding it...
                            // but in normal use this can't happen...
                            response_list.insert(std::pair<std::string, unsigned char>(tkn, sts));

                            if (*msg_response->status() == SRUP::UPDATE::SRUP_UPDATE_SUCCESS)
                                BOOST_LOG_TRIVIAL(info) << "SRUP_UPDATE_SUCCESS";
                            else
                            {
                                // We don't have a SRUP_UPDATE_SUCCESS response - so first we must delete the token
                                // from the transactions list to prevent activation...

                                std::string transactionToken(msg_response->token());

                                std::map<std::string, std::string>::iterator iter = transactions_list.find(
                                        transactionToken);
                                if (iter != transactions_list.end())
                                    transactions_list.erase(transactionToken);
                                else
                                {
                                    BOOST_LOG_TRIVIAL(warning)
                                        << "SRUP_MESSAGE_TYPE_RESPONSE message contained unknown token"
                                        << transactionToken;
                                }

                                if (*msg_response->status() == SRUP::UPDATE::SRUP_UPDATE_FAIL_DIGEST)
                                    BOOST_LOG_TRIVIAL(info) << "SRUP_UPDATE_FAIL_DIGEST";

                                else if (*msg_response->status() == SRUP::UPDATE::SRUP_UPDATE_FAIL_FILE)
                                    BOOST_LOG_TRIVIAL(info) << "SRUP_UPDATE_FAIL_FILE";
                                else if (*msg_response->status() == SRUP::UPDATE::SRUP_UPDATE_FAIL_SERVER)
                                    BOOST_LOG_TRIVIAL(info) << "SRUP_UPDATE_FAIL_SERVER";
                                else
                                {
                                    // We shouldn't be able to receive any other status codes
                                    // But just in case...
                                    BOOST_LOG_TRIVIAL(error) << "SRUP_MESSAGE_TYPE_RESPONSE had invalid status code: "
                                                             << *msg_response->status();
                                    throw -1;
                                }
                            }
                            return;
                        }
                    }
                    else
                    {
                        // We didn't verify okay...
                        // We should also log the fact that the verify operation failed...
                        BOOST_LOG_TRIVIAL(warning) << "Operation Failed – SRUP RESP Message did not Verify";
                    }
                } // if_key_is_good

                // Don't forget to clean up!
                delete (msg_response);

            } // if_is_response
        } // if_version...
    } // if_deserialize
    delete (msg_generic);
}

int SRUP_Server::disconnect()
{
    while (want_write())
        loop_write();

    mosqpp::lib_cleanup();
    return mosqpp::mosquittopp::disconnect();
}

bool SRUP_Server::send_init_message(char *target, char *token, char *url, char *digest)
{
    if (!topics_list.empty())
    {
        std::string pub_topic(target);
        pub_topic = "SRUP/" + pub_topic;

        // Check to see if we're subscribed to the topic for the target...
        if ((std::find(topics_list.begin(), topics_list.end(), pub_topic) != topics_list.end()))
        {
            SRUP_MSG_INIT *msg_init;

            unsigned char *serial_data;
            int len;

            msg_init = new (SRUP_MSG_INIT);
            msg_init->target(target);
            msg_init->token(token);
            msg_init->url(url);
            msg_init->digest(digest);
            msg_init->sequenceID(&seqid);

            // Signing the message must be the last step before serializing it...
            msg_init->Sign(pvkeyfile);

            serial_data = msg_init->Serialized();
            len = msg_init->SerializedLength();

            publish(NULL, pub_topic.c_str(), len, serial_data);
            loop_write();

            // Increment the (sending) sequence ID...
            seqid++;

            // Now that we have sent the INITIATE message - we should add it to the open transactions list...
            transactions_list.insert(std::pair<std::string, std::string>(token, target));

            delete (msg_init);
            return true;
        }

        else
        {
            // We're not subscribed to the right topic for this target...
            BOOST_LOG_TRIVIAL(error) << "SEND_INIT : TARGET does not match MQTT TOPIC subscription";
            return false;
        }
    }
    else
        return false;
}

bool SRUP_Server::send_activate_message(char *token)
{
    if (!topics_list.empty())
    {
        SRUP_MSG_ACTIVATE *msg_activate;

        unsigned char *serial_data;
        int len;

        std::string target;
        std::string transactionToken(token);

        // Check to see if the token is in our open transaction list...
        std::map<std::string, std::string>::iterator iter = transactions_list.find(transactionToken);
        if (iter != transactions_list.end())
        {
            target = transactions_list.at(token);

            msg_activate = new (SRUP_MSG_ACTIVATE);
            msg_activate->token(token);
            msg_activate->sequenceID(&seqid);

            msg_activate->Sign(pvkeyfile);

            serial_data = msg_activate->Serialized();
            len = msg_activate->SerializedLength();

            publish(NULL, ("SRUP/" + target).c_str(), len, serial_data);
            loop_write();

            seqid++;

            transactions_list.erase(transactionToken);
            delete (msg_activate);
            return true;
        }
        else
            return false;
    }
    else
        return false;
}

unsigned char SRUP_Server::get_response(std::string token)
{
    loop_read();
    return response_list.at(token);
}

bool SRUP_Server::check_for_response(std::string token)
{
    std::map<std::string, unsigned char>::iterator iter;
    iter = response_list.find(token);

    // Check to see if we have a response for this token...
    if (iter == response_list.end())
    {
        // Token not found - so start counting...
        // Check to see if it's already in the not_found list...
        std::map<std::string, int>::iterator not_found_search = not_found.find(token);
        if (not_found_search == not_found.end())
        {
            // Create an item in the map for the token...
            not_found.insert(std::pair<std::string, int>(token, 1));
        }
        else
        {
            // Check to see if the number of attempts > timeout threshold
            if (not_found.at(token) > Response_Timeout)
                return true;
            else
                not_found.at(token)++;
        }

        BOOST_LOG_TRIVIAL(debug) << token;
        //std::this_thread::yield();

        // Now sleep this thread for a quarter-second before returning - to give everything a chance to catch-up
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        return false;
    }
    else
    {
        // We have the response...
        // If we have this on our not_found list we should remove it
        std::map<std::string, int>::iterator iter = not_found.find(token);
        if (iter != not_found.end())
            not_found.erase(iter);
        return true;
    }
}

bool SRUP_Server::response_not_found(std::string token)
{
    std::map<std::string, int>::iterator iter = not_found.find(token);

    // If token is in the not_found list - then return true...
    return !(iter == not_found.end());
}

void SRUP_Server::set_public_key(const char *public_key)
{
    keyfile = new char[strlen(public_key)];
    strcpy(keyfile, public_key);
}

void SRUP_Server::set_private_key(const char *private_key)
{
    pvkeyfile = new char[strlen(private_key)];
    strcpy(pvkeyfile, private_key);
}

void SRUP_Server::add_topic(const char *target)
{
    // We get passed a TARGET ID - and we turn it into a SRUP (MQTT) Topic by prefixing it with "SRUP/"
    topics_list.push_front("SRUP/" + std::string(target));
}

void SRUP_Server::do_subscribe()
{
    for (std::string s : topics_list)
    {
        // As we're not using the subscribe callback - the MessageID is NULL...
        subscribe(NULL, s.c_str(), QOS_Setting);
    }
}

SRUP_Server::~SRUP_Server()
{

}
