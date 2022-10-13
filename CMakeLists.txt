cmake_minimum_required(VERSION 3.22)
project(sucic C)

set(CMAKE_C_STANDARD 17)

include_directories(
            inc
            /usr/include/openssl
        )

add_executable(sucic src/main.c src/sucic_utils.c src/ec_xg.c)

target_link_libraries(sucic PUBLIC -lcrypto -lssl)
