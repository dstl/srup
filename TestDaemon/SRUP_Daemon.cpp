//
// Created by AJ Poulter on 18/07/2016.
//

#include "SRUP_Daemon.h"
#include "Fetcher/gen-cpp/Fetcher.h"
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/protocol/TBinaryProtocol.h>

namespace SRUP
{
    namespace FETCHER
    {
        static const unsigned char FETCHER_RETURN_OK = 0x00;
        static const unsigned char FETCHER_RETURN_DIGEST_ERROR = 0x01;
        static const unsigned char FETCHER_RETURN_SERVER_ERROR = 0x02;
        static const unsigned char FETCHER_RETURN_FILE_ERROR = 0x03;
    }
}

using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;

SRUP_Daemon::SRUP_Daemon(const char *id, const char *host, int port) : mosquittopp(id)
{
    done = false;
    listentopic = NULL;

    pvkeyfile = NULL;
    keyfile = NULL;

    int keepalive = DEFAULT_KEEP_ALIVE;
    connect(host, port, keepalive);
}

void SRUP_Daemon::on_message(const struct mosquitto_message *message)
{
    unsigned char buf[MAX_PAYLOAD];

    SRUP_MSG_INIT *msg_init;
    SRUP_MSG_ACTIVATE *msg_activate;

    SRUP_MSG_GENERIC *msg_generic;

    char msgtype;

    if ((keyfile == NULL) || (pvkeyfile == NULL))
    {
        BOOST_LOG_TRIVIAL(error) << "Certificate keyfiles not set";
    }
    else
    {
        if (listentopic != NULL)
        {
            if (!strcmp(message->topic, listentopic))
            {
                msg_generic = new(SRUP_MSG_GENERIC);

                std::memset(buf, 0, MAX_PAYLOAD * sizeof(char));
                std::memcpy(buf, message->payload, MAX_PAYLOAD * sizeof(char));

                if (msg_generic->DeSerialize(buf))
                {
                    char version = *msg_generic->version();
                    if (SRUP::SRUP_VERSION == version)
                    {
                        msgtype = *msg_generic->msgtype();

                        if (SRUP::SRUP_MESSAGE_TYPE_INITIATE == msgtype)
                        {
                            msg_init = new(SRUP_MSG_INIT);
                            msg_init->DeSerialize(buf);
                            SRUP_Daemon::on_SRUP_Init_message(msg_init);
                        }

                        if (msgtype == SRUP::SRUP_MESSAGE_TYPE_ACTIVATE)
                        {
                            msg_activate = new (SRUP_MSG_ACTIVATE);
                            msg_activate->DeSerialize(buf);
                            SRUP_Daemon::on_SRUP_Activate_message(msg_activate);
                        }
                    }
                    else
                        BOOST_LOG_TRIVIAL(warning) << "Invalid SRUP Version";
                }
                else
                    BOOST_LOG_TRIVIAL(error) << "SRUP Message did not deserialize";

                delete (msg_generic);
            }
        }
    }
}

void SRUP_Daemon::listen_topic(char *x)
{
    if (listentopic != NULL)
        delete (listentopic);

    listentopic = new char[strlen(x)+1];
    strncpy(listentopic, x, strlen(x));
    listentopic[strlen(x)]=0;
}

char *SRUP_Daemon::listen_topic()
{
    return listentopic;
}

SRUP_Daemon::~SRUP_Daemon()
{
    if (listentopic != NULL)
        delete (listentopic);
}

void SRUP_Daemon::on_connect(int rc)
{
    if (!rc)
        subscribe(NULL, listentopic, 1);
}

int SRUP_Daemon::disconnect()
{
    while (want_write())
        loop_write();

    mosqpp::lib_cleanup();
    return mosqpp::mosquittopp::disconnect();
}

void SRUP_Daemon::set_public_key(const char *public_key)
{
    keyfile = new char[strlen(public_key)+1];
    strcpy(keyfile, public_key);
    keyfile[strlen(public_key)]=0;
}

void SRUP_Daemon::set_private_key(const char *private_key)
{
    pvkeyfile = new char[strlen(private_key)+1];
    strcpy(pvkeyfile, private_key);
    pvkeyfile[strlen(private_key)]=0;
}

void SRUP_Daemon::on_SRUP_Activate_message(SRUP_MSG_ACTIVATE *msg_activate)
{
    if (msg_activate->Verify(keyfile))
    {
        BOOST_LOG_TRIVIAL(info) << "Message Type: SRUP_MESSAGE_TYPE_ACTIVATE";
        BOOST_LOG_TRIVIAL(info) << "Token: " << msg_activate->token();
        //done = true;

        // Invoke Thrift service...
        boost::shared_ptr<TSocket> socket(new TSocket("localhost", 9091));
        boost::shared_ptr<TTransport> transport(new TBufferedTransport(socket));
        boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));

        FetcherClient fetcher(protocol);
        bool rv;

        try
        {
            transport->open();
            rv = fetcher.START_STOP();
            transport->close();
            if (!rv)
                BOOST_LOG_TRIVIAL(error) << "ACTIVATION UNSUCCESSFUL";
        }

        catch (TTransportException e)
        {
            BOOST_LOG_TRIVIAL(error) << "THRIFT TRANSPORT ERROR";
        }

        catch (TApplicationException e)
        {
            BOOST_LOG_TRIVIAL(error) << "THRIFT APPLICATION EXCEPTION";
        }

        delete (msg_activate);
    }
    else
    {
        BOOST_LOG_TRIVIAL(warning) << "Operation Failed – SRUP ACT Message did not Verify";

    }
}

void SRUP_Daemon::on_SRUP_Init_message(SRUP_MSG_INIT *msg_init)
{
    SRUP_MSG_RESPONSE *msg_response;
    unsigned char *serial_data;
    int len;

    if (msg_init->Verify(keyfile))
    {
        BOOST_LOG_TRIVIAL(info) << "Message Type: SRUP_MESSAGE_TYPE_INITIATE";
        BOOST_LOG_TRIVIAL(info) << "Target: " << msg_init->target();
        BOOST_LOG_TRIVIAL(info) << "Token: " << msg_init->token();
        BOOST_LOG_TRIVIAL(info) << "URL: " << msg_init->url();
        BOOST_LOG_TRIVIAL(info) << "Digest: " << msg_init->digest();

        // Now we'll use the Fetcher Thrift Service to get the file...
        boost::shared_ptr<TSocket> socket(new TSocket("localhost", 9091));
        boost::shared_ptr<TTransport> transport(new TBufferedTransport(socket));
        boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));

        FetcherClient fetcher(protocol);
        char rv = 0;

        try
        {
            transport->open();
            rv = fetcher.FETCH_FROM_URL(msg_init->url(), msg_init->digest());
            transport->close();
        }

        catch (TTransportException e)
        {
            BOOST_LOG_TRIVIAL(error) << "THRIFT TRANSPORT ERROR";
        }

        catch (TApplicationException e)
        {
            BOOST_LOG_TRIVIAL(error) << "THRIFT APPLICATION EXCEPTION";
        }

        msg_response = new (SRUP_MSG_RESPONSE);

        msg_response->token(msg_init->token());

        if (rv == SRUP::FETCHER::FETCHER_RETURN_OK)
        {
            msg_response->status(SRUP::UPDATE::SRUP_UPDATE_SUCCESS);
            BOOST_LOG_TRIVIAL(info) << "RESPONSE = SRUP_UPDATE_SUCCESS";
        }
        else if (rv == SRUP::FETCHER::FETCHER_RETURN_DIGEST_ERROR)
        {
            msg_response->status(SRUP::UPDATE::SRUP_UPDATE_FAIL_DIGEST);
            BOOST_LOG_TRIVIAL(info) << "RESPONSE = SRUP_UPDATE_FAIL_DIGEST";
        }
        else if (rv == SRUP::FETCHER::FETCHER_RETURN_FILE_ERROR)
        {
            msg_response->status(SRUP::UPDATE::SRUP_UPDATE_FAIL_FILE);
            BOOST_LOG_TRIVIAL(info) << "RESPONSE = SRUP_UPDATE_FAIL_FILE";
        }
        else if (rv == SRUP::FETCHER::FETCHER_RETURN_SERVER_ERROR)
        {
            msg_response->status(SRUP::UPDATE::SRUP_UPDATE_FAIL_SERVER);
            BOOST_LOG_TRIVIAL(info) << "RESPONSE = SRUP_UPDATE_FAIL_SERVER";
        }
        else
        {
            // rv can only take the above values - but being defensive...
            // TODO: Add new error return for internal error?
            msg_response->status(SRUP::UPDATE::SRUP_UPDATE_FAIL_SERVER);
            BOOST_LOG_TRIVIAL(info) << "RESPONSE = SRUP_UPDATE_FAIL_SERVER";
        }

        msg_response->Sign(pvkeyfile);

        serial_data = msg_response->Serialized();
        len = msg_response->SerializedLength();

        publish(NULL, listentopic, len, serial_data);

        // Don't forget to clean up!
        delete (msg_init);
        delete (msg_response);
    }
    else
    {
        BOOST_LOG_TRIVIAL(warning) << "Operation Failed – SRUP INIT Message did not Verify";
    }
    return;
}
