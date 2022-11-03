cmake_minimum_required(VERSION 3.22)
project(suci VERSION 1.0.6 DESCRIPTION "5G SUCI C library")

set(CMAKE_C_STANDARD 17)
set(CMDLINE_TEST 1)

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

include_directories(
            inc
            /usr/include/openssl
        )

if(CMDLINE_TEST)
add_definitions(-DSUCIC_TEST_ENABLED)
add_executable(suci src/suci_utils.c src/suci_calcs.c src/suci_test.c)
else()
add_library(suci SHARED src/suci_utils.c src/suci_calcs.c inc/suci_test.h)
set_target_properties(suci PROPERTIES
        VERSION ${PROJECT_VERSION}
        PUBLIC_HEADER inc/suci_calcs.h
        SOVERSION 1
)
endif()

target_link_libraries(suci PUBLIC -lcrypto -lssl)
