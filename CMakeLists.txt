cmake_minimum_required(VERSION 3.16)
project(device-discovery LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(NOT WIN32)
  message(FATAL_ERROR
    "device-discovery runs on Windows only; the Linux box is the device that is "
    "discovered, not the host running this tool.")
endif()

find_package(Threads REQUIRED)

# ---- libssh2 ----------------------------------------------------------------
# vcpkg (recommended): vcpkg install libssh2:x64-windows and configure with
#   -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
find_package(Libssh2 CONFIG QUIET)
if(NOT Libssh2_FOUND)
  find_package(libssh2 CONFIG QUIET)
endif()

if(TARGET Libssh2::libssh2_shared)
  set(LIBSSH2_TARGET Libssh2::libssh2_shared)
elseif(TARGET Libssh2::libssh2_static)
  set(LIBSSH2_TARGET Libssh2::libssh2_static)
elseif(TARGET Libssh2::libssh2)
  set(LIBSSH2_TARGET Libssh2::libssh2)
else()
  find_path(LIBSSH2_INCLUDE_DIR libssh2.h)
  find_library(LIBSSH2_LIBRARY NAMES ssh2 libssh2)
  if(NOT LIBSSH2_INCLUDE_DIR OR NOT LIBSSH2_LIBRARY)
    message(FATAL_ERROR
      "libssh2 development files not found. Install them, e.g.:\n"
      "  vcpkg install libssh2:x64-windows\n"
      "and re-run CMake with\n"
      "  -DCMAKE_TOOLCHAIN_FILE=<vcpkg-root>/scripts/buildsystems/vcpkg.cmake")
  endif()
endif()

# ---- Core library shared by the executable and the tests --------------------
add_library(device_discovery_core STATIC
  src/platform/windows_sockets.cpp
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
target_link_libraries(device_discovery_core PUBLIC Threads::Threads ws2_32 iphlpapi)

# Windows 8.1 / Server 2012 R2 and later: required for GetIpNetTable2().
target_compile_definitions(device_discovery_core PUBLIC
  _WIN32_WINNT=0x0603
  WIN32_LEAN_AND_MEAN
  NOMINMAX
)

if(LIBSSH2_TARGET)
  target_link_libraries(device_discovery_core PUBLIC ${LIBSSH2_TARGET})
else()
  target_include_directories(device_discovery_core PUBLIC ${LIBSSH2_INCLUDE_DIR})
  target_link_libraries(device_discovery_core PUBLIC ${LIBSSH2_LIBRARY})
endif()

# ---- Warning flags ----------------------------------------------------------
if(MSVC)
  set(DEVICE_DISCOVERY_WARNINGS /W4 /permissive-)
else()
  set(DEVICE_DISCOVERY_WARNINGS -Wall -Wextra -Wpedantic)
endif()
target_compile_options(device_discovery_core PRIVATE ${DEVICE_DISCOVERY_WARNINGS})

# ---- Executable -------------------------------------------------------------
add_executable(device-discovery src/main.cpp)
target_link_libraries(device-discovery PRIVATE device_discovery_core)
target_compile_options(device-discovery PRIVATE ${DEVICE_DISCOVERY_WARNINGS})

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
    target_compile_options(${test_name} PRIVATE ${DEVICE_DISCOVERY_WARNINGS})
    add_test(NAME ${test_name} COMMAND ${test_name})
  endforeach()
endif()
