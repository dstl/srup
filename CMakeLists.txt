cmake_minimum_required(VERSION 3.5)

add_subdirectory(Test/lib/googletest)

project(SRUP)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -DHAVE_INTTYPES_NETINET_IN_H")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/build")

ADD_DEFINITIONS(-DBOOST_LOG_DYN_LINK)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

FIND_PACKAGE(Boost 1.54 COMPONENTS log REQUIRED)

set(MOSQUITTO_DIR "/Code/C/mqtt/mosquitto/mosquitto-1.4.9/")
set(OPENSSL_DIR "/usr/local/Cellar/openssl/1.0.2h_1/")
set(THRIFT_DIR "/usr/local/include/thrift")


include_directories(/${MOSQUITTO_DIR}/lib/ ${MOSQUITTO_DIR}/lib/cpp/ ${CMAKE_SOURCE_DIR} ${OPENSSL_DIR}/include/ ${THRIFT_DIR} ${Boost_INCLUDE_DIR})
link_directories(${MOSQUITTO_DIR}lib/cpp/ ${CMAKE_SOURCE_DIR}/build/Debug/ ${OPENSSL_DIR}/lib/ /usr/local/lib)

set(LIB_SOURCE_FILES SRUP.cpp SRUP.h SRUP_Init.cpp SRUP_Init.h SRUP_Response.cpp SRUP_Response.h SRUP_Activate.cpp SRUP_Activate.h SRUP_Generic.cpp SRUP_Generic.h SRUP_Crypto.cpp SRUP_Crypto.h)
set(DAEMON_SOURCE_FILES TestDaemon/main.cpp TestDaemon/SRUP_Daemon.cpp TestDaemon/SRUP_Daemon.h)
set(SERVER_SOURCE_FILES TestServer/main.cpp TestServer/SRUP_Server.cpp TestServer/SRUP_Server.h)
set(FETCHER_THRIFT_SOURCE_FILES TestDaemon/Fetcher/gen-cpp/Fetcher.cpp TestDaemon/Fetcher/gen-cpp/fetcher_types.cpp TestDaemon/Fetcher/gen-cpp/fetcher_constants.cpp)
set(SERVER_THRIFT_SOURCE_FILES TestServer/thrift/gen-cpp/SRUP.cpp TestServer/thrift/gen-cpp/SRUP_Service_types.cpp TestServer/thrift/gen-cpp/SRUP_Service_constants.cpp)

add_library(SRUP_Lib SHARED ${LIB_SOURCE_FILES})
target_link_libraries(SRUP_Lib libcrypto.a)

add_executable(SRUP_Daemon ${DAEMON_SOURCE_FILES} ${FETCHER_THRIFT_SOURCE_FILES})
add_executable(SRUP_Server ${SERVER_SOURCE_FILES} ${SERVER_THRIFT_SOURCE_FILES})

target_link_libraries(SRUP_Daemon thrift libmosquittopp.1.dylib libSRUP_Lib.dylib ${Boost_LIBRARIES})
target_link_libraries(SRUP_Server Threads::Threads thrift libmosquittopp.1.dylib libSRUP_Lib.dylib ${Boost_LIBRARIES})


project(SRUP_Tests)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")

if (APPLE)
    add_definitions(-DGTEST_USE_OWN_TR1_TUPLE)
    add_definitions(-D__GLIBCXX__)
endif (APPLE)

include_directories(./Test/lib/googletest/include ./Test/lib/googletest)

add_executable(runAllTests ./Test/tests.cpp ${LIB_SOURCE_FILES})
target_link_libraries(runAllTests gtest gtest_main libSRUP_Lib.dylib libcrypto.a)
