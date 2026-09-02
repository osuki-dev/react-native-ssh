project(OsukiSsh)
cmake_minimum_required(VERSION 3.9.0)

set(PACKAGE_NAME OsukiSsh)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)

# One shared library per package: Nitro HybridObjects (C++) + the Rust core
# (static archive, linked in) = libOsukiSsh.so.
add_library(${PACKAGE_NAME} SHARED
        src/main/cpp/cpp-adapter.cpp
        ../cpp/HybridSshClient.cpp
        ../cpp/HybridSshConnection.cpp
        ../cpp/HybridSshShell.cpp
)

# Prebuilt Rust static library for this ABI (scripts/build-rust-android.sh).
set(RNSSH_LIB "${CMAKE_CURRENT_SOURCE_DIR}/rust-libs/${ANDROID_ABI}/librnssh_ffi.a")
if(NOT EXISTS "${RNSSH_LIB}")
  message(FATAL_ERROR "[OsukiSsh] missing ${RNSSH_LIB}. Run scripts/build-rust-android.sh or restrict reactNativeArchitectures to arm64-v8a,x86_64.")
endif()
add_library(rnssh_ffi STATIC IMPORTED)
set_target_properties(rnssh_ffi PROPERTIES IMPORTED_LOCATION "${RNSSH_LIB}")

# Add Nitrogen specs
include(${CMAKE_SOURCE_DIR}/../nitrogen/generated/android/OsukiSsh+autolinking.cmake)

include_directories(
        "src/main/cpp"
        "../cpp"
)

find_library(LOG_LIB log)

target_link_libraries(
        ${PACKAGE_NAME}
        rnssh_ffi
        ${LOG_LIB}
        android
)

# Keep the exported surface minimal; only JNI_OnLoad needs to be visible.
target_link_options(${PACKAGE_NAME} PRIVATE -Wl,--exclude-libs,ALL -Wl,--gc-sections)
