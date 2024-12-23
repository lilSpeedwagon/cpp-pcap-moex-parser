cmake_minimum_required(VERSION 3.5)

project(moex_parser)
set (CMAKE_CXX_STANDARD 17)

# headers
set(HEADERS_DIR ./src)

# sources
set(SOURCES
    src/main.cpp
)

# build executable
add_executable(${PROJECT_NAME} ${SOURCES})

# setup libraries headers
target_include_directories(${PROJECT_NAME} PRIVATE
    ${HEADERS_DIR}
)
target_compile_options(${PROJECT_NAME} PRIVATE
)
