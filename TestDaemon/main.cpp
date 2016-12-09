//
// Created by AJ Poulter on 27/04/2016.
//

// This is a (simplified) example implementation of a SRUP Daemon process.
// We run a simple MQTT Client to get any MQTT messages from the broker; and we run the SRUP daemon to process
// any SRUP messages received. The deamon process in turn uses a Thrift server to handle the fetch & check associated
// with the update message type.

// Devices should only be subscribed to one MQTT topic - which should be SRUP/<DEVICE_ID>
// So we can assume that any message that this deamon receives is meant for it...

#include "SRUP_Daemon.h"

#define CLIENT_ID "Daemon -"
#define MQTT_PORT 1883

static void init_log(void)
{
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
            boost::log::keywords::file_name = "SRUP_Daemon_%3N.log",
            boost::log::keywords::rotation_size = 10 * 1024 * 1024,
            boost::log::keywords::min_free_space = 30 * 1024 * 1024,
            boost::log::keywords::time_based_rotation = boost::log::sinks::file::rotation_at_time_point(0, 0, 0),
            boost::log::keywords::open_mode = std::ios_base::app);

    fsSink->set_formatter(logFmt);

    fsSink->locked_backend()->auto_flush(true);
}

int main(int argc, char *argv[])
{
    class SRUP_Daemon *daemon;
    int rc;

    char *client_id;
    char *topic;

    int port = MQTT_PORT;

    init_log();

    if (argc != 5)
    {
        BOOST_LOG_TRIVIAL(error) << "Invalid command-line options...";
        BOOST_LOG_TRIVIAL(error) << "Should be: ... <DEV_ID> <MQTT_BROKER> <DEV_PV_KEY_FILE> <SV_PUB_KEY_FILE>";
        return 99;
    }

    // Define the topic as 'SRUP/' + the device's ID...
    topic = new char[5+strlen(argv[1])];
    strncpy(topic, "SRUP/", 5);
    strncat(topic, argv[1], strlen(argv[1]));

    client_id = new char[8+strlen(argv[1])];
    strncpy(client_id, CLIENT_ID, 8);
    strncat(client_id, argv[1], strlen(argv[1]));

    daemon = new SRUP_Daemon(client_id, argv[2], port);
    daemon->set_private_key(argv[3]);
    daemon->set_public_key(argv[4]);
    daemon->listen_topic(topic);

    rc = daemon->loop();

    if (rc)
    {
        BOOST_LOG_TRIVIAL(error) << "Cannot connect to MQTT Broker";
        return 1;
    }

    BOOST_LOG_TRIVIAL(info) << "Starting Service";

    while (!daemon->done)
        daemon->loop();

    daemon->disconnect();
    delete topic;
    return 0;
}