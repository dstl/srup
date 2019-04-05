cmake_minimum_required(VERSION 3.5)

project(SRUPLib)

if(UNIX AND NOT APPLE)
    # e.g. It's LINUX...
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wl,--no-as-needed -ldl -DHAVE_INTTYPES_NETINET_IN_H")
endif()

if (APPLE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -DHAVE_INTTYPES_NETINET_IN_H")
    # Ugly fix – since neither find_package nor pkgconfig can find homebrew openssl on Mac... :-(
    set(OPENSSL_ROOT_DIR "/usr/local/Cellar/openssl/1.0.2q")
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}")

add_definitions(-DBOOST_LOG_DYN_LINK)

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED)

if(OPENSSL_FOUND)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
else()
    message(FATAL_ERROR "OpenSSL not found")
endif()

include_directories(${CMAKE_SOURCE_DIR} ${OpenSSL_INCLUDE_DIR} ${Boost_INCLUDE_DIR})
link_directories(${CMAKE_SOURCE_DIR} /usr/local/lib)

set(LIB_SOURCE_FILES SRUP.cpp SRUP.h SRUP_Init.cpp SRUP_Init.h SRUP_Response.cpp SRUP_Response.h SRUP_Activate.cpp
        SRUP_Activate.h SRUP_Generic.cpp SRUP_Generic.h SRUP_Crypto.cpp SRUP_Crypto.h SRUP_Action.h SRUP_Action.cpp
        SRUP_Data.cpp SRUP_Data.h SRUP_Join.cpp SRUP_Join.h SRUP_Join_Cmd.cpp SRUP_Join_Cmd.h SRUP_ID_REQ.cpp
        SRUP_ID_REQ.h SRUP_Resign.cpp SRUP_Resign.h SRUP_Terminate.cpp SRUP_Terminate.h SRUP_Deregister.cpp
        SRUP_Deregister.h SRUP_Deregister_Cmd.cpp SRUP_Deregister_Cmd.h SRUP_Simple.cpp SRUP_Simple.h SRUP_Group_Add.cpp
        SRUP_Group_Add.h SRUP_Group.cpp SRUP_Group.h SRUP_Group_Delete.cpp SRUP_Group_Delete.h SRUP_Human_Join.cpp
        SRUP_Human_Join.h SRUP_Observed_Join.cpp SRUP_Observed_Join.h SRUP_Human_Join_Resp.cpp SRUP_Human_Join_Resp.h
        SRUP_Observed_Base.cpp SRUP_Observed_Base.h SRUP_Observed_Join_Resp.cpp SRUP_Observed_Join_Resp.h
        SRUP_Observation_Req.cpp SRUP_Observation_Req.h SRUP_Group_Destroy.cpp SRUP_Group_Destroy.h)

add_library(SRUP_Lib SHARED ${LIB_SOURCE_FILES})
target_link_libraries(SRUP_Lib OpenSSL::Crypto)

####################################################################################################################

project(pySRUPLib)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -DHAVE_INTTYPES_NETINET_IN_H")

find_package(PythonLibs 3.7 REQUIRED)
include_directories(${PYTHON_INCLUDE_DIR})

if(APPLE)
    find_package(Boost COMPONENTS log REQUIRED)
else()
    find_package(Boost COMPONENTS python3 log REQUIRED)
endif()

include_directories(${Boost_INCLUDE_DIR})

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

add_definitions(-DBOOST_LOG_DYN_LINK)
include_directories(${CMAKE_SOURCE_DIR} ${OpenSSL_INCLUDE_DIR}  ${Boost_INCLUDE_DIR} ${PYTHON_INCLUDE_DIR})

set(LIB_SOURCE_FILES SRUP.cpp SRUP.h SRUP_Init.cpp SRUP_Init.h SRUP_Response.cpp SRUP_Response.h SRUP_Activate.cpp
        SRUP_Activate.h SRUP_Generic.cpp SRUP_Generic.h SRUP_Crypto.cpp SRUP_Crypto.h SRUP_Action.h SRUP_Action.cpp
        SRUP_Data.cpp SRUP_Data.h SRUP_Join.cpp SRUP_Join.h SRUP_Join_Cmd.cpp SRUP_Join_Cmd.h SRUP_ID_REQ.cpp
        SRUP_ID_REQ.h SRUP_Resign.cpp SRUP_Resign.h SRUP_Terminate.cpp SRUP_Terminate.h SRUP_Deregister.cpp
        SRUP_Deregister.h SRUP_Deregister_Cmd.cpp SRUP_Deregister_Cmd.h SRUP_Simple.cpp SRUP_Simple.h SRUP_Group_Add.cpp
        SRUP_Group_Add.h SRUP_Group.cpp SRUP_Group.h SRUP_Group_Delete.cpp SRUP_Group_Delete.h SRUP_Human_Join.cpp
        SRUP_Human_Join.h SRUP_Observed_Join.cpp SRUP_Observed_Join.h SRUP_Human_Join_Resp.cpp SRUP_Human_Join_Resp.h
        SRUP_Observed_Base.cpp SRUP_Observed_Base.h SRUP_Observed_Join_Resp.cpp SRUP_Observed_Join_Resp.h
        SRUP_Observation_Req.cpp SRUP_Observation_Req.h SRUP_Group_Destroy.cpp SRUP_Group_Destroy.h)

set(HELPER_SOURCE_FILES pySRUP/pySRUPLib.cpp pySRUP/pySRUP_Action pySRUP/pySRUP pySRUP/pySRUP_Response
        pySRUP/pySRUP_Initiate pySRUP/pySRUP_Data.cpp pySRUP/pySRUP_Data.h
        pySRUP/pySRUP_Join.cpp pySRUP/pySRUP_Join.h pySRUP/pySRUP_Observed.cpp pySRUP/pySRUP_Observed.h)

add_library(pySRUPLib MODULE ${HELPER_SOURCE_FILES} ${LIB_SOURCE_FILES} SRUP_Simple.cpp SRUP_Simple.h)

if(APPLE)
    set(PYTHON_LIBRARY "/usr/local/opt/python3/Frameworks/Python.framework/Versions/3.7/lib/libpython3.7.dylib")
    set(BOOST_PYTHON_LIBRARY "/usr/local/opt/boost-python3/lib/libboost_python37.dylib")
endif()

link_directories(/usr/local/lib)
target_link_libraries(pySRUPLib ${PYTHON_LIBRARY} ${Boost_LIBRARIES} ${BOOST_PYTHON_LIBRARY} OpenSSL::Crypto)
set_target_properties(pySRUPLib PROPERTIES PREFIX "")

####################################################################################################################
#
# Uncomment this section if you want to build the google test suite...
# Note: you'll need to install the framework in Test/lib/googletest...

project(SRUP_Tests)

# Here's a really ugly kludge to fix the fact that this block cannot find openssl - even using the method in the
# main section. :-(
set(manual_openssl_include_path "/usr/local/Cellar/openssl/1.0.2q/include/")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")
add_subdirectory(Test/lib/googletest)

if (APPLE)
    add_definitions(-DGTEST_USE_OWN_TR1_TUPLE)
    add_definitions(-D__GLIBCXX__)
endif (APPLE)

include_directories(./Test/lib/googletest/include ./Test/lib/googletest ${manual_openssl_include_path})

add_executable(runAllTests ./Test/tests.cpp ${LIB_SOURCE_FILES})
if (APPLE)
    target_link_libraries(runAllTests gtest gtest_main libSRUP_Lib.dylib libcrypto.a)
else()
    target_link_libraries(runAllTests gtest gtest_main libSRUP_Lib.so libcrypto.a)
endif()