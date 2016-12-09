//
// Created by AJ Poulter on 27/04/2016.
//

// This is a (simplified) example implementation of a SRUP Server.
// We create two threads here - one of which will run the MQTT Client / SRUP process; and the other will be the
// Thrift service that enables us to run a Python REST interface to the SRUP Server.

#include "SRUP_Server.h"

#include "thrift/gen-cpp/SRUP.h"

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TBufferTransports.h>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <thread>

using namespace ::apache::thrift;
using namespace ::apache::thrift::protocol;
using namespace ::apache::thrift::transport;
using namespace ::apache::thrift::server;

using boost::shared_ptr;

// For teh purposes of the example, we'll hard-code identify of example devices.
#define TARGET "3Hus7Y9E"
#define TARGET2 "l8Hd6kcM"

#define CLIENT_ID "C2 Server"
#define MQTT_PORT 1883

SRUP_Server *mqtt_server;

void MQTT_Init(const char* broker, const char* private_key, const char* public_key)
{
    int rc;

    mqtt_server = new SRUP_Server(CLIENT_ID, broker, MQTT_PORT);

    mqtt_server->add_topic(TARGET);
    mqtt_server->add_topic(TARGET2);
    mqtt_server->do_subscribe();

    mqtt_server->set_private_key(private_key);
    mqtt_server->set_public_key(public_key);
    rc = mqtt_server->loop();

    while (rc)
    {
        rc = mqtt_server->loop();
    }

    while (mqtt_server->mqtt_active)
        mqtt_server->loop();

    mqtt_server->disconnect();
}

class SRUPHandler : virtual public SRUPIf
{
public:

    SRUPHandler(const char* broker, const char* private_key, const char* public_key)
    {
        std::thread t1(MQTT_Init, broker, private_key, public_key);
        t1.detach();
    }

    void SendInit(std::string& token, const std::string& target, const std::string& url, const std::string& digest)
    {
        std::string generated_token;

        boost::uuids::uuid uuid_token = generator();
        generated_token = boost::lexical_cast<std::string>(uuid_token);

        char* ctarget = new char[target.length()+1];
        char* ctoken = new char[generated_token.length()+1];
        char* curl = new char[url.length()+1];
        char* cdigest = new char[digest.length()+1];

        strcpy(ctarget, target.c_str());
        strcpy(ctoken, generated_token.c_str());
        strcpy(curl, url.c_str());
        strcpy(cdigest, digest.c_str());

        if (mqtt_server->send_init_message(ctarget, ctoken, curl, cdigest))
            token = generated_token;
        else
            token = "";

        // clean-up
        delete[] ctarget;
        delete[] ctoken;
        delete[] curl;
        delete[] cdigest;

        return;
    }

    bool SendActivate(const std::string& token)
    {
        bool rv;

        char* ctoken = new char[token.length()+1];
        strcpy(ctoken, token.c_str());

        rv = mqtt_server->send_activate_message(ctoken);

        delete[] ctoken;
        return rv;
    }

    int8_t GetResp(const std::string& token)
    {
        bool done = false;
        int8_t rv;

        // We want to avoid an infinite loop here - so check_for_response counts the number of attempts
        // and will eventually return true to end the loop...
        while (!done)
            done = mqtt_server->check_for_response(token);

        // We must now check to see if we have a response message - or if we just timed-out...
        if (!mqtt_server->response_not_found(token))
        {
            rv = mqtt_server->get_response(token);

            return rv;
        }
        else
        {
            // If we timed-out - then we need to throw an exception.
            TokenNotFoundException e;
            e.token=token;
            throw e; //RESP_NOT_RECIEVED_EXCEPTION...
        }
    }

    boost::uuids::random_generator generator;
};

static void init_log(void)
{
    // Setup boost logging - with severity set to INFO...
    // Output to the console and log file(s).

    boost::log::add_common_attributes();
    boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::info);

    auto fmtTimeStamp = boost::log::expressions::format_date_time <boost::posix_time::ptime> ("TimeStamp", "%Y-%m-%d %H:%M:%S");
    auto fmtSeverity = boost::log::expressions::attr <boost::log::trivial::severity_level> ("Severity");

    boost::log::formatter logFmt = boost::log::expressions::format("[%1%] [%2%]     \t %3%") % fmtTimeStamp % fmtSeverity % boost::log::expressions::smessage;

   // console sink
    auto consoleSink = boost::log::add_console_log(std::clog);
    consoleSink->set_formatter(logFmt);

    // fs sink
    auto fsSink = boost::log::add_file_log(
            boost::log::keywords::file_name = "SRUP_Server_%3N.log",
            boost::log::keywords::rotation_size = 10 * 1024 * 1024,
            boost::log::keywords::min_free_space = 30 * 1024 * 1024,
            boost::log::keywords::time_based_rotation = boost::log::sinks::file::rotation_at_time_point(0, 0, 0),
            boost::log::keywords::open_mode = std::ios_base::app);

    fsSink->set_formatter(logFmt);

    fsSink->locked_backend()->auto_flush(true);
}

int main(int argc, char *argv[])
{
    init_log();

    if (argc != 4)
    {
        BOOST_LOG_TRIVIAL(error) << "Invalid command-line options specified.";
        BOOST_LOG_TRIVIAL(error) << "Should be: ... <MQTT_BROKER> <SV_PV_KEY_FILE> <DEV_PUB_KEY_FILE>";
        return 1;
    }

    int thrift_port = 9090;
    try
    {
        // Create the thread to handle the SRUP messages - passing in the two keyfiles we're using...
        shared_ptr<SRUPHandler> handler(new SRUPHandler(argv[1], argv[2], argv[3]));

        // Now we've done that - the main thread will run the Thrift service...
        shared_ptr<TProcessor> processor(new SRUPProcessor(handler));
        shared_ptr<TServerTransport> serverTransport(new TServerSocket(thrift_port));
        shared_ptr<TTransportFactory> transportFactory(new TBufferedTransportFactory());
        shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());
        TSimpleServer server(processor, serverTransport, transportFactory, protocolFactory);
        BOOST_LOG_TRIVIAL (info) << "Starting Service";
        server.serve();
    }
    catch (TException& tx)
    {
        BOOST_LOG_TRIVIAL(error) << "Could not establish the Thrift service. Error: " << tx.what();
        return 2;
    }
}