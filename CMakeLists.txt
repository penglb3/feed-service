cmake_minimum_required(VERSION 3.18)
project(feed-service)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-volatile -Wno-address-of-packed-member -fmacro-prefix-map=${CMAKE_SOURCE_DIR}/= -fcoroutines")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Boost REQUIRED COMPONENTS charconv json)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

include(ExternalProject)
include(ProcessorCount)
include(CheckCXXCompilerFlag)
ProcessorCount(N)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

CHECK_CXX_COMPILER_FLAG("-march=native" COMPILER_SUPPORTS_MARCH_NATIVE)
if(COMPILER_SUPPORTS_MARCH_NATIVE)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
endif()

CHECK_CXX_COMPILER_FLAG("-flto" COMPILER_SUPPORTS_FLTO)
if(COMPILER_SUPPORTS_FLTO)
  if (CMAKE_BUILD_TYPE STREQUAL Release)    
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto")
  endif()
endif()

add_executable(echo_server src/echo_server.cc)
target_include_directories(echo_server PUBLIC include)
add_executable(feed-service src/http_server.cc)
target_include_directories(feed-service PUBLIC include)
target_link_libraries(echo_server uring)
target_link_libraries(feed-service Boost::charconv Threads::Threads OpenSSL::Crypto OpenSSL::SSL Boost::json)