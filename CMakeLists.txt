cmake_minimum_required(VERSION 3.12)

project(bbTLS)

set(WOLFROOT "/Users/kojo/wolfWorks/wolfssl")
set(CMAKE_C_FLAGS "-O2 -g -DWOLFSSL_USER_SETTINGS "
)

include_directories(. ./inc ${WOLFROOT})

add_library(libyt SHARED)

target_sources(libyt
    PRIVATE
    ${WOLFROOT}/wolfcrypt/src/random.c
    ${WOLFROOT}/wolfcrypt/src/aes.c
    ${WOLFROOT}/wolfcrypt/src/sha.c
    ${WOLFROOT}/wolfcrypt/src/sha256.c
    ${WOLFROOT}/wolfcrypt/src/sha512.c
    ${WOLFROOT}/wolfcrypt/src/hash.c
    ${WOLFROOT}/wolfcrypt/src/rsa.c
    ${WOLFROOT}/wolfcrypt/src/ecc.c
    ${WOLFROOT}/wolfcrypt/src/curve25519.c
    ${WOLFROOT}/wolfcrypt/src/fe_low_mem.c
    ${WOLFROOT}/wolfcrypt/src/ge_low_mem.c
    ${WOLFROOT}/wolfcrypt/src/fe_operations.c
    ${WOLFROOT}/wolfcrypt/src/ge_operations.c
    ${WOLFROOT}/wolfcrypt/src/curve448.c
    ${WOLFROOT}/wolfcrypt/src/ge_448.c
    ${WOLFROOT}/wolfcrypt/src/fe_448.c
    ${WOLFROOT}/wolfcrypt/src/sp_c64.c
    ${WOLFROOT}/wolfcrypt/src/sp_int.c
    ${WOLFROOT}/wolfcrypt/src/wolfmath.c
    ${WOLFROOT}/wolfcrypt/src/asn.c
    ${WOLFROOT}/wolfcrypt/src/pwdbased.c
    ${WOLFROOT}/wolfcrypt/src/dsa.c
    ${WOLFROOT}/wolfcrypt/src/hmac.c
    ${WOLFROOT}/wolfcrypt/src/coding.c
    ${WOLFROOT}/wolfcrypt/src/wc_encrypt.c
    ${WOLFROOT}/wolfcrypt/src/wc_port.c
    ${WOLFROOT}/wolfcrypt/src/memory.c
)

target_sources(libyt
    PRIVATE
    ${WOLFROOT}/wolfcrypt/src/memory.c
    src/common/exception.c
    src/common/extern.c
    src/common/mem.c
)

target_sources(libyt
    PRIVATE
    src/tls/ext.c
    src/tls/hs1_cHello.c
    src/tls/hs2_sHello.c
    src/tls/hs4_certificate.c
    src/tls/hs4_newSesTicket.c
    src/tls/hs5_endEarlyData.c
    src/tls/hs7_cKeyExchange.c
    src/tls/hs8_certficate.c
    src/tls/hs8_encExt.c
    src/tls/hs11_certficate.c
    src/tls/hs15_certVerify.c
    src/tls/hs20_finished.c
    src/tls/hs24_keyUpdate.c
    src/tls/hs254_message_hash.c
    src/tls/rec.c
    src/tls/tls.c
)

#add_executable(unit-test)
#target_sources(unit-test
#    PRIVATE
#    src/tests/unit-test.c
#)
#target_link_libraries(unit-test libyt)

add_executable(tls-client)
target_sources(tls-client
    PRIVATE
    src/main.c
)

target_link_libraries(tls-client libyt)
