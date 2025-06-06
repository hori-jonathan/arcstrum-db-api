cmake_minimum_required(VERSION 3.15)
project(db-api)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(libs/crow)

add_executable(db-api main.cpp)

target_sources(db-api PRIVATE
    libs/sqlite/sqlite3.c
    libs/multipart-parser/multipart_parser.c
)

target_include_directories(db-api PRIVATE
    libs/crow/include
    libs/json/single_include
    libs/asio/asio/include
    libs/sqlite
    libs/multipart-parser         # <-- add this line
    extern/jwt-cpp/include
)

find_package(OpenSSL REQUIRED)
target_link_libraries(db-api PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if (UNIX AND NOT APPLE)
    target_link_libraries(db-api PRIVATE pthread)
endif()
