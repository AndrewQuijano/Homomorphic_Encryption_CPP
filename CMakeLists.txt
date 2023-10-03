cmake_minimum_required(VERSION 3.10.0)

#project name
project (hello_cmake)

# Configure Source & Binary Directories ---------------------------------------
SET (PROJECT_ROOT "${PROJECT_SOURCE_DIR}")
SET (PROJECT_SOURCE_DIR "${PROJECT_SOURCE_DIR}/src")
SET (PROJECT_BINARY_DIR "${PROJECT_BINARY_DIR}/bin")
MESSAGE ("Source path: ${PROJECT_SOURCE_DIR}")
MESSAGE ("Binary path: ${PROJECT_BINARY_DIR}")

add_executable(hello_age main.cpp age.cpp)
