project(jitsi-jnisrtp-native C)
cmake_minimum_required(VERSION 3.0)


#################################################
# CMAKE CONFIGURABLE VARIABLES
################################################

# Release with debug info build type as default
if (NOT CMAKE_BUILD_TYPE)
	message(STATUS "No build type selected, using RelWithDebInfo")
	set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif ()

set(CMAKE_C_STANDARD 11)

set(JITSI_SRTP_JAVA_HEADERS_DIR "${JITSI_SRTP_JAVA_HEADERS_DIR}"
    CACHE PATH "Path to directory with javah generated headers")

message(STATUS "javah headers directory (JITSI_SRTP_JAVA_HEADERS_DIR): `${JITSI_SRTP_JAVA_HEADERS_DIR}`")


#################################################
# LOAD EXTERNAL LIBRARIES INFO
#################################################

find_package(JNI)
find_package(OpenSSL)

if (APPLE AND NOT OPENSSL_FOUND)
    set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@1.1/")
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib/libcrypto.dylib")
endif()

message(STATUS "OpenSSL locaiton: ${OPENSSL_CRYPTO_LIBRARY}")
message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")

#################################################
# COMPILER SETTINGS
#################################################

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# SETTINGS FOR UNIX COMPILER
if (CMAKE_C_COMPILER_ID MATCHES "Clang" OR CMAKE_C_COMPILER_ID MATCHES "AppleClang" OR CMAKE_C_COMPILER_ID MATCHES "GNU")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic -Wall -Wextra")
endif ()

# SETTINGS FOR VISUAL STUDIO COMPILER
if (CMAKE_C_COMPILER_ID MATCHES "MSVC")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Wall")
endif ()

message(STATUS "Compiler flags (CMAKE_C_FLAGS): ${CMAKE_C_FLAGS}")


#################################################
# LIBRARY NAMING CONFIGURATION
#################################################

if (APPLE)
    set(CMAKE_SHARED_LIBRARY_SUFFIX_C ".jnilib")
endif ()


#################################################
# TARGETS DEFINITION
#################################################

list(APPEND jitsi_srtp_native_jni_sources
	Hmac.c
	OpenSslWrapperLoader.c
	SrtpCipherCtrOpenSsl.c
)

list(APPEND jitsi_srtp_native_dependencies
    ${OPENSSL_CRYPTO_LIBRARY}
)

set(JNI_TARGET_NAME jnisrtp)

add_library(${JNI_TARGET_NAME} SHARED
    ${jitsi_srtp_native_jni_sources}
)

target_link_libraries(${JNI_TARGET_NAME} PRIVATE
    ${jitsi_srtp_native_dependencies}
)

target_include_directories(${JNI_TARGET_NAME} PRIVATE
    ${JNI_INCLUDE_DIRS}
    ${JITSI_SRTP_JAVA_HEADERS_DIR}
    ${OPENSSL_INCLUDE_DIR}
)


#################################################
# INSTALL LIBRARY
#################################################
install(TARGETS ${JNI_TARGET_NAME}
        RUNTIME
            DESTINATION ${CMAKE_INSTALL_PREFIX}
        LIBRARY
            DESTINATION ${CMAKE_INSTALL_PREFIX})

if (WIN32)
    install(FILES $<TARGET_PDB_FILE:${JNI_TARGET_NAME}>
            DESTINATION ${CMAKE_INSTALL_PREFIX} OPTIONAL)
endif ()
