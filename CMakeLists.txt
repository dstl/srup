cmake_minimum_required(VERSION 3.5)

project(SRUPLib)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -DHAVE_INTTYPES_NETINET_IN_H")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}")

add_definitions(-DBOOST_LOG_DYN_LINK)

find_package(Boost REQUIRED)

set(OPENSSL_DIR "/usr/local/Cellar/openssl/1.0.2h_1/")

include_directories(${CMAKE_SOURCE_DIR} ${OPENSSL_DIR}/include/ ${Boost_INCLUDE_DIR})
link_directories(${CMAKE_SOURCE_DIR} ${OPENSSL_DIR}/lib/ /usr/local/lib)

set(LIB_SOURCE_FILES SRUP.cpp SRUP.h SRUP_Init.cpp SRUP_Init.h SRUP_Response.cpp SRUP_Response.h SRUP_Activate.cpp
        SRUP_Activate.h SRUP_Generic.cpp SRUP_Generic.h SRUP_Crypto.cpp SRUP_Crypto.h SRUP_Action.h SRUP_Action.cpp
        SRUP_Data.cpp SRUP_Data.h)

add_library(SRUP_Lib SHARED ${LIB_SOURCE_FILES})
target_link_libraries(SRUP_Lib libcrypto.a)

####################################################################################################################

project(pySRUPLib)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -DHAVE_INTTYPES_NETINET_IN_H")

find_package(PythonLibs 3.6 REQUIRED)
include_directories(${PYTHON_INCLUDE_DIR})

find_package(Boost COMPONENTS python3 log REQUIRED)
include_directories(${Boost_INCLUDE_DIR})

set(OPENSSL_DIR "/usr/local/Cellar/openssl/1.0.2h_1/")
add_definitions(-DBOOST_LOG_DYN_LINK)
include_directories(${CMAKE_SOURCE_DIR} ${OPENSSL_DIR}/include/ ${Boost_INCLUDE_DIR} ${PYTHON_INCLUDE_DIR})

set(LIB_SOURCE_FILES SRUP.cpp SRUP.h SRUP_Init.cpp SRUP_Init.h SRUP_Response.cpp SRUP_Response.h SRUP_Activate.cpp
        SRUP_Activate.h SRUP_Generic.cpp SRUP_Generic.h SRUP_Crypto.cpp SRUP_Crypto.h SRUP_Action.h SRUP_Action.cpp
        SRUP_Data.cpp SRUP_Data.h)

set(HELPER_SOURCE_FILES pySRUP/pySRUPLib.cpp pySRUP/pySRUP_Action pySRUP/pySRUP pySRUP/pySRUP_Response
        pySRUP/pySRUP_Initiate pySRUP/pySRUP_Data.cpp pySRUP/pySRUP_Data.h)

add_library(pySRUPLib MODULE ${HELPER_SOURCE_FILES} ${LIB_SOURCE_FILES})

if(APPLE)
    set(PYTHON_LIBRARY "/usr/local/Cellar/python3/3.6.3/Frameworks/Python.framework/Versions/3.6/lib/libpython3.6.dylib")
endif()

link_directories(${OPENSSL_DIR}/lib/ /usr/local/lib)
target_link_libraries(pySRUPLib ${PYTHON_LIBRARY} ${Boost_LIBRARIES} libcrypto.a)
set_target_properties(pySRUPLib PROPERTIES PREFIX "")

####################################################################################################################
#
# Uncomment this section if you want to build the google test suite...
# Note: you'll need to install the framework in Test/lib/googletest...
#
# project(SRUP_Tests)
#
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")
# add_subdirectory(Test/lib/googletest)
#
# if (APPLE)
#    add_definitions(-DGTEST_USE_OWN_TR1_TUPLE)
#    add_definitions(-D__GLIBCXX__)
# endif (APPLE)
#
# include_directories(./Test/lib/googletest/include ./Test/lib/googletest)
#
# add_executable(runAllTests ./Test/tests.cpp ${LIB_SOURCE_FILES})
# target_link_libraries(runAllTests gtest gtest_main libSRUP_Lib.dylib libcrypto.a)

