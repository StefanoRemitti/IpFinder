cmake_minimum_required(VERSION 3.16)
project(device-discovery LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(WARNING "device-discovery targets Linux; other platforms are unsupported.")
endif()

find_package(Threads REQUIRED)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(LIBSSH2 IMPORTED_TARGET libssh2)
endif()
if(NOT LIBSSH2_FOUND)
  find_path(LIBSSH2_INCLUDE_DIR libssh2.h)
  find_library(LIBSSH2_LIBRARY NAMES ssh2 libssh2)
  if(NOT LIBSSH2_INCLUDE_DIR OR NOT LIBSSH2_LIBRARY)
    message(FATAL_ERROR
      "libssh2 development files not found. Install them, e.g.:\n"
      "  Debian/Ubuntu: sudo apt install libssh2-1-dev\n"
      "  Fedora/RHEL:   sudo dnf install libssh2-devel\n"
      "  Arch:          sudo pacman -S libssh2")
  endif()
endif()

# ---- Core library shared by the executable and the tests --------------------
add_library(device_discovery_core STATIC
  src/network/interface_discovery.cpp
  src/network/arp_discovery.cpp
  src/scanner/port_scanner.cpp
  src/scanner/ssh_detector.cpp
  src/scanner/subnet_sweep.cpp
  src/parser/ifconfig_parser.cpp
  src/ssh/ssh_client.cpp
  src/threading/thread_pool.cpp
  src/output/formatter.cpp
)
target_include_directories(device_discovery_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(device_discovery_core PUBLIC Threads::Threads)
target_compile_options(device_discovery_core PRIVATE -Wall -Wextra -Wpedantic)

if(LIBSSH2_FOUND)
  target_link_libraries(device_discovery_core PUBLIC PkgConfig::LIBSSH2)
else()
  target_include_directories(device_discovery_core PUBLIC ${LIBSSH2_INCLUDE_DIR})
  target_link_libraries(device_discovery_core PUBLIC ${LIBSSH2_LIBRARY})
endif()

# ---- Executable -------------------------------------------------------------
add_executable(device-discovery src/main.cpp)
target_link_libraries(device-discovery PRIVATE device_discovery_core)
target_compile_options(device-discovery PRIVATE -Wall -Wextra -Wpedantic)

# ---- Tests ------------------------------------------------------------------
option(BUILD_TESTING "Build the unit tests" ON)
if(BUILD_TESTING)
  enable_testing()

  foreach(test_name
      test_thread_pool
      test_interface_discovery
      test_ifconfig_parser
      test_ssh_detector
      test_subnet_sweep
      test_formatter
      test_arp_discovery)
    add_executable(${test_name} tests/${test_name}.cpp)
    target_link_libraries(${test_name} PRIVATE device_discovery_core)
    target_include_directories(${test_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    target_compile_options(${test_name} PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME ${test_name} COMMAND ${test_name})
  endforeach()
endif()
