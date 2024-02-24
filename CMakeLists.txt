cmake_minimum_required(VERSION 3.28.2)
set(PROJECT_NAME file_encryption_tool)
project(${PROJECT_NAME})

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)


# add your source files
set(SOURCE_FILES 
  src/main.cpp
  )
set (HEADER_FILES
  )

# Add the CMAKE_EXPORT_COMPILE_COMMANDS option
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)



add_executable(${PROJECT_NAME} ${SOURCE_FILES} ${HEADER_FILES})

# Include the 'include/' directory
target_include_directories(${PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  )

include_directories(/usr/include/cryptopp)

target_link_libraries(${PROJECT_NAME} cryptopp)

set(CMAKE_ERROR_DEPRECATED TRUE)
set(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION TRUE)
