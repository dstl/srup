cmake_minimum_required(VERSION 3.5)

project(SRUPLib)

if(UNIX AND NOT APPLE)
    # e.g. It's LINUX...
    EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE)
    message( STATUS "Architecture: ${ARCHITECTURE}" )

    if( ${ARCHITECTURE} MATCHES "arm" )
        set( RPI True )
        message( STATUS "Raspberry Pi: True" )
    else()
        set( RPI False )
        message( STATUS "Raspberry Pi: False" )
    endif()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wl,--no-as-needed -ldl -DHAVE_INTTYPES_NETINET_IN_H")
endif()

if (APPLE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -DHAVE_INTTYPES_NETINET_IN_H -I/usr/local/opt/openssl/include")
    # Ugly fix – since neither find_package nor pkgconfig can find homebrew openssl on Mac... :-(
    set(PKG_CONFIG_PATH "/usr/local/opt/openssl/lib/pkgconfig")
    # set(OPENSSL_ROOT_DIR "/usr/local/Cellar/openssl/1.0.2t")
    set(OPENSSL_ROOT_DIR "/usr/local/Cellar/openssl@1.1/1.1.1h/")
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}")

add_definitions(-DBOOST_LOG_DYN_LINK)

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED)

if(OPENSSL_FOUND)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
else()
    message(FATAL_ERROR "OpenSSL not found.")
endif()

include_directories(${CMAKE_SOURCE_DIR} ${OpenSSL_INCLUDE_DIR} ${Boost_INCLUDE_DIR})
link_directories(${CMAKE_SOURCE_DIR} ${OpenSSL_LIB_DIR} /usr/local/lib)

set(LIB_SOURCE_FILES SRUP.cpp SRUP.h SRUP_Init.cpp SRUP_Init.h SRUP_Response.cpp SRUP_Response.h SRUP_Activate.cpp
        SRUP_Activate.h SRUP_Generic.cpp SRUP_Generic.h SRUP_Crypto.cpp SRUP_Crypto.h SRUP_Action.h SRUP_Action.cpp
        SRUP_Data.cpp SRUP_Data.h SRUP_Join.cpp SRUP_Join.h SRUP_Join_Cmd.cpp SRUP_Join_Cmd.h SRUP_ID_REQ.cpp
        SRUP_ID_REQ.h SRUP_Resign.cpp SRUP_Resign.h SRUP_Terminate.cpp SRUP_Terminate.h SRUP_Deregister.cpp
        SRUP_Deregister.h SRUP_Deregister_Cmd.cpp SRUP_Deregister_Cmd.h SRUP_Simple.cpp SRUP_Simple.h 
        SRUP_Human_Join.cpp SRUP_Human_Join.h SRUP_Observed_Join.cpp SRUP_Observed_Join.h SRUP_Human_Join_Resp.cpp
        SRUP_Human_Join_Resp.h SRUP_Observed_Base.cpp SRUP_Observed_Base.h SRUP_Observed_Join_Resp.cpp
        SRUP_Observed_Join_Resp.h SRUP_Observation_Req.cpp SRUP_Observation_Req.h SRUP_Syndicated_Data.cpp
        SRUP_Syndicated_Data.h SRUP_Syndicated_Action.cpp SRUP_Syndicated_Action.h SRUP_Syndicated_ID_REQ.cpp
        SRUP_Syndicated_ID_REQ.h SRUP_Syndicated_C2_Req.cpp SRUP_Syndicated_C2_Req.h SRUP_Syndicated_End_Request.cpp
        SRUP_Syndicated_End_Request.h SRUP_Syndicated_Terminate.cpp SRUP_Syndicated_Terminate.h
        SRUP_Syndicated_Device_Count.cpp SRUP_Syndicated_Device_Count.h SRUP_Syndicated_Device_List.cpp
        SRUP_Syndicated_Device_List.h SRUP_Syndication_Request.cpp SRUP_Syndication_Request.h SRUP_Syndication_Init.cpp
        SRUP_Syndication_Init.h)

add_library(SRUP_Lib SHARED ${LIB_SOURCE_FILES})
#target_link_libraries(SRUP_Lib OpenSSL::Crypto)
target_link_libraries(SRUP_Lib ${OPENSSL_LIBRARIES})

####################################################################################################################

project(pySRUPLib)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -DHAVE_INTTYPES_NETINET_IN_H")

find_package(PythonLibs 3 REQUIRED)
include_directories(${PYTHON_INCLUDE_DIR})

if(UNIX AND NOT APPLE)
    # e.g. It's LINUX...
    # ...Check to see if we're a Raspberry Pi - proxied by checking for an ARM CPU...
    EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE)
    message( STATUS "Architecture: ${ARCHITECTURE}" )

    if( ${ARCHITECTURE} MATCHES "arm" )
        set( RPI True )
        message( STATUS "Raspberry Pi: True" )
    else()
        set( RPI False )
        message( STATUS "Raspberry Pi: False" )
    endif()
endif()

if(APPLE)
    find_package(Boost COMPONENTS log REQUIRED)
elseif(RPI)
    find_package(Boost COMPONENTS python-py35 log REQUIRED)
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
        SRUP_Deregister.h SRUP_Deregister_Cmd.cpp SRUP_Deregister_Cmd.h SRUP_Simple.cpp SRUP_Simple.h
        SRUP_Human_Join.cpp SRUP_Human_Join.h SRUP_Observed_Join.cpp SRUP_Observed_Join.h SRUP_Human_Join_Resp.cpp
        SRUP_Human_Join_Resp.h SRUP_Observed_Base.cpp SRUP_Observed_Base.h SRUP_Observed_Join_Resp.cpp
        SRUP_Observed_Join_Resp.h SRUP_Observation_Req.cpp SRUP_Observation_Req.h SRUP_Syndicated_Data.cpp
        SRUP_Syndicated_Data.h SRUP_Syndicated_Action.cpp SRUP_Syndicated_Action.h SRUP_Syndicated_ID_REQ.cpp
        SRUP_Syndicated_ID_REQ.h SRUP_Syndicated_C2_Req.cpp SRUP_Syndicated_C2_Req.h SRUP_Syndicated_End_Request.cpp
        SRUP_Syndicated_End_Request.h SRUP_Syndicated_Terminate.cpp SRUP_Syndicated_Terminate.h
        SRUP_Syndicated_Device_Count.cpp SRUP_Syndicated_Device_Count.h SRUP_Syndicated_Device_List.cpp
        SRUP_Syndicated_Device_List.h SRUP_Syndication_Request.cpp SRUP_Syndication_Request.h SRUP_Syndication_Init.cpp
        SRUP_Syndication_Init.h)

set(HELPER_SOURCE_FILES pySRUP/pySRUPLib.cpp pySRUP/pySRUP_Action pySRUP/pySRUP pySRUP/pySRUP_Response
        pySRUP/pySRUP_Initiate pySRUP/pySRUP_Data.cpp pySRUP/pySRUP_Data.h pySRUP/pySRUP_Join.cpp pySRUP/pySRUP_Join.h
        pySRUP/pySRUP_Observed.cpp pySRUP/pySRUP_Observed.h pySRUP/pySRUP_Syndicated_ID_REQ.cpp
        pySRUP/pySRUP_Syndicated_ID_REQ.h pySRUP/pySRUP_Syndicated_Action.cpp pySRUP/pySRUP_Syndicated_Action.h
        pySRUP/pySRUP_Syndicated_Data.cpp pySRUP/pySRUP_Syndicated_Data.h pySRUP/pySRUP_Syndicated_Device_Count.cpp
        pySRUP/pySRUP_Syndicated_Device_Count.h pySRUP/pySRUP_Syndicated_Device_List.cpp
        pySRUP/pySRUP_Syndicated_Device_List.h pySRUP/pySRUP_Syndicated_C2_Request.cpp
        pySRUP/pySRUP_Syndicated_C2_Request.h pySRUP/pySRUP_Syndication_Init.cpp pySRUP/pySRUP_Syndication_Init.h)

add_library(pySRUPLib MODULE ${HELPER_SOURCE_FILES} ${LIB_SOURCE_FILES} SRUP_Simple.cpp SRUP_Simple.h)

if(APPLE)
    set(PYTHON_LIBRARY "/usr/local/opt/python3/Frameworks/Python.framework/Versions/3.8/lib/libpython3.8.dylib")
    set(BOOST_PYTHON_LIBRARY "/usr/local/opt/boost-python3/lib/libboost_python37.dylib")
endif()

link_directories(/usr/local/lib)
#target_link_libraries(pySRUPLib ${PYTHON_LIBRARY} ${Boost_LIBRARIES} ${BOOST_PYTHON_LIBRARY} OpenSSL::Crypto)
target_link_libraries(pySRUPLib ${PYTHON_LIBRARY} ${Boost_LIBRARIES} ${BOOST_PYTHON_LIBRARY} ${OPENSSL_LIBRARIES})

set_target_properties(pySRUPLib PROPERTIES PREFIX "")

####################################################################################################################
#
# Uncomment this section if you want to build the google test suite...
# Note: you'll need to install the framework in Test/lib/googletest...

# project(SRUP_Tests)

# Here's a really ugly kludge to fix the fact that this block cannot find openssl - even using the method in the
# main section. :-(
# set(manual_openssl_include_path "/usr/local/Cellar/openssl/1.0.2q/include/")

# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")
# add_subdirectory(Test/lib/googletest)

# if (APPLE)
#     add_definitions(-DGTEST_USE_OWN_TR1_TUPLE)
#     add_definitions(-D__GLIBCXX__)
# endif (APPLE)
# 
# include_directories(./Test/lib/googletest/include ./Test/lib/googletest ${manual_openssl_include_path})
# 
# add_executable(runAllTests ./Test/tests.cpp ${LIB_SOURCE_FILES})
# if (APPLE)
#    target_link_libraries(runAllTests gtest gtest_main libSRUP_Lib.dylib ${OPENSSL_LIBRARIES})
# else()
#     target_link_libraries(runAllTests gtest gtest_main libSRUP_Lib.so ${OPENSSL_LIBRARIES})
# endif()
