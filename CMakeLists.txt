cmake_minimum_required(VERSION 3.22)
project(sucic VERSION 1.0.3 DESCRIPTION "5G SUCI C library")

set(CMAKE_C_STANDARD 17)
set(CMDLINE_TEST 1)

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

include_directories(
            inc
            /usr/include/openssl
        )

if(CMDLINE_TEST)
add_definitions(-DSUCIC_TEST_ENABLED)
add_executable(sucic src/sucic_utils.c src/sucic_calcs.c src/sucic_test.c)
else()
add_library(sucic SHARED src/sucic_utils.c src/sucic_calcs.c inc/sucic_test.h)
set_target_properties(sucic PROPERTIES
        VERSION ${PROJECT_VERSION}
        PUBLIC_HEADER inc/sucic_calcs.h
        SOVERSION 1
)
endif()

target_link_libraries(sucic PUBLIC -lcrypto -lssl)
