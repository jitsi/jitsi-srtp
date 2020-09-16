/*
 * Copyright @ 2016 - present 8x8, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "org_jitsi_srtp_crypto_JitsiOpenSslProvider.h"
#include <openssl/evp.h>
#include <openssl/err.h>

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslWrapperLoader
 * Method:    OpenSsl_Init
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL
Java_org_jitsi_srtp_crypto_JitsiOpenSslProvider_OpenSSL_1Init
  (JNIEnv *env, jclass clazz)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L || (LIBRESSL_VERSION_NUMBER && LIBRESSL_VERSION_NUMBER < 0x20700000L)
    /* these init calls are deprecated in OpenSSL 1.1 */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
#endif

    return JNI_TRUE;
}

