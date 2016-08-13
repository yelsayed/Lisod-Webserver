cmake_minimum_required(VERSION 3.3)
project(Lisod_Webserver)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -lssl -lcrypto")
set(SSL_INCLUDE_DIR /usr/local/openssl/include)

file(GLOB_RECURSE SOURCE_FILES "*/*.c" "*/*.py" "*/*.sql" "*/*.css" "*/*.crt" "*/*.key" "*/*.h" "*/*.txt" "*/*.html")


find_package(openssl COMPONENTS system filesystem REQUIRED)
include_directories(${SSL_INCLUDE_DIR})
add_executable(Lisod_Webserver ${SOURCE_FILES})