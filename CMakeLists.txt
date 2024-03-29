cmake_minimum_required(VERSION 3.15)
project(src)

set(CMAKE_CXX_STANDARD 14)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

# add extra include directories
include_directories(/usr/local/include)

# add extra lib directories
link_directories(/usr/local/lib)

file(GLOB SRC "*.cpp")
file(GLOB AXML_PARSER "axml_parser/*.cpp")

add_executable(src ${SRC} ${AXML_PARSER})

# specify the dependency on an extra library
target_link_libraries(src libzip.a)

# Boost.
set(BOOST_MIN_VERSION "1.53.0")
find_package(Boost ${BOOST_MIN_VERSION}
        COMPONENTS system iostreams program_options locale REQUIRED)
include_directories(SYSTEM ${Boost_INCLUDE_DIRS})
add_definitions(
        -DBOOST_MAJOR_VERSION=${Boost_MAJOR_VERSION}
        -DBOOST_MINOR_VERSION=${Boost_MINOR_VERSION}
)
target_link_libraries(src ${Boost_LIBRARIES})