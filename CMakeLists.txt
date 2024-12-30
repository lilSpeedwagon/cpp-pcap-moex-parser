cmake_minimum_required(VERSION 3.5)

project(moex_parser LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)  
set(CMAKE_CXX_STANDARD_REQUIRED ON)  

# headers
set(HEADERS_DIR ./src)

# sources
set(SOURCES
    src/main.cpp
    src/utils/binary.cpp
)

# build executable
add_executable(${PROJECT_NAME} ${SOURCES})

# setup libraries headers
target_include_directories(${PROJECT_NAME} PRIVATE
    ${HEADERS_DIR}
)
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)
target_compile_options(${PROJECT_NAME} PRIVATE
)
