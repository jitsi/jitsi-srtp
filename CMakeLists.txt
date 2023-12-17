cmake_minimum_required(VERSION 3.18)
project(jitsisrtp_${JITSI_SRTP_LIBSSL_VERSION} C)

option(JITSI_SRTP_LIBSSL_VERSION "libssl version")
if (${JITSI_SRTP_LIBSSL_VERSION} MATCHES "1.1")
    set(_JITSI_SRTP_LIBSSL_VERSION "1.1...2")
else ()
    set(_JITSI_SRTP_LIBSSL_VERSION "${JITSI_SRTP_LIBSSL_VERSION}...99")
endif ()

if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
        set(JITSI_SYSTEM_PROCESSOR "x86-64")
    else ()
        set(JITSI_SYSTEM_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR})
    endif ()
    set(CMAKE_INSTALL_PREFIX "${CMAKE_CURRENT_LIST_DIR}/src/main/resources/${CMAKE_SYSTEM_NAME}-${JITSI_SYSTEM_PROCESSOR}" CACHE PATH "default install path" FORCE)
    string(TOLOWER ${CMAKE_INSTALL_PREFIX} CMAKE_INSTALL_PREFIX)
    message(STATUS "CMAKE_INSTALL_PREFIX not set, defaulting to >${CMAKE_INSTALL_PREFIX}<")
endif ()

find_package(OpenSSL ${_JITSI_SRTP_LIBSSL_VERSION} REQUIRED)
# TODO: CMake 3.24 will support import targets for JNI to only query JNI without AWT; use when released
find_package(JNI)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_library(${PROJECT_NAME} SHARED
            src/main/native/JitsiCipherOpenSsl.c
            src/main/native/JitsiHmacOpenSsl.c
            src/main/native/JitsiOpenSslProvider.c
            src/main/native/SrtpCipherGcmAuthOnlyOpenSsl.c
            )

target_link_libraries(${PROJECT_NAME} PRIVATE
                      ${JAVA_JVM_LIBRARY}
                      OpenSSL::Crypto
                      )

target_include_directories(${PROJECT_NAME} PUBLIC
                           ${OPENSSL_INCLUDE_DIR}
                           ${JNI_INCLUDE_DIRS}
                           ${CMAKE_CURRENT_LIST_DIR}/target/native/javah
                           )

install(TARGETS ${PROJECT_NAME}
        RUNTIME DESTINATION "."
        LIBRARY DESTINATION "."
        )

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "ppc64el")
    string(TOLOWER ${CMAKE_SYSTEM_NAME} CMAKE_SYSTEM_NAME_LOWER)
    install(TARGETS ${PROJECT_NAME}
            LIBRARY DESTINATION "../${CMAKE_SYSTEM_NAME_LOWER}-ppc64le"
            )
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "ppc64le")
    string(TOLOWER ${CMAKE_SYSTEM_NAME} CMAKE_SYSTEM_NAME_LOWER)
    install(TARGETS ${PROJECT_NAME}
            LIBRARY DESTINATION "../${CMAKE_SYSTEM_NAME_LOWER}-ppc64el"
            )
endif ()
