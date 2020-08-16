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

#include "org_jitsi_srtp_crypto_OpenSslAesCipherSpi.h"

#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>

/*
 * Class:     org_jitsi_srtp_OpenSslAesCipherSpi
 * Method:    AES_CTR_CTX_create
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL
Java_org_jitsi_srtp_crypto_OpenSslAesCipherSpi_AES_1CTR_1CTX_1create
  (JNIEnv *env, jclass clazz)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    return (jlong) (intptr_t) ctx;
}

/*
 * Class:     org_jitsi_srtp_OpenSslAesCipherSpi
 * Method:    AES_CTR_CTX_destroy
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_org_jitsi_srtp_crypto_OpenSslAesCipherSpi_AES_1CTR_1CTX_1destroy
  (JNIEnv *env, jclass clazz, jlong ctx)
{
    if (ctx) {
        EVP_CIPHER_CTX *ctx_ = (EVP_CIPHER_CTX *) (intptr_t) ctx;
        EVP_CIPHER_CTX_free(ctx_);
    }
}

/*
 * Class:     org_jitsi_srtp_OpenSslAesCipherSpi
 * Method:    AES_CTR_CTX_init
 * Signature: (J[B)Z
 */
JNIEXPORT jboolean JNICALL
Java_org_jitsi_srtp_crypto_OpenSslAesCipherSpi_AES_1CTR_1CTX_1init
  (JNIEnv *env, jclass clazz, jlong ctx, jbyteArray key)
{
    jboolean r = JNI_FALSE;
    unsigned char *key_ = (unsigned char*)(*env)->GetPrimitiveArrayCritical(env, key, NULL);
    if (!key_)
      goto exit;

    jsize keySize = (*env)->GetArrayLength(env, key);
    switch (keySize)
    {
    case 16:
      r = EVP_CipherInit_ex((EVP_CIPHER_CTX *) (intptr_t) ctx, EVP_aes_128_ctr(), NULL, key_, NULL, 1);
      break;
    case 24:
      r = EVP_CipherInit_ex((EVP_CIPHER_CTX *) (intptr_t) ctx, EVP_aes_192_ctr(), NULL, key_, NULL, 1);
      break;
    case 32:
      r = EVP_CipherInit_ex((EVP_CIPHER_CTX *) (intptr_t) ctx, EVP_aes_256_ctr(), NULL, key_, NULL, 1);
      break;
    }

exit:
    if (key_)
        (*env)->ReleasePrimitiveArrayCritical(env, key, key_, 0);
    return r;
}

/*
 * Class:     org_jitsi_srtp_OpenSslAesCipherSpi
 * Method:    AES_CTR_CTX_process
 * Signature: (J[B[BII)Z
 */
JNIEXPORT jboolean JNICALL
Java_org_jitsi_srtp_crypto_OpenSslAesCipherSpi_AES_1CTR_1CTX_1process
  (JNIEnv *env, jclass clazz, jlong ctx, jbyteArray iv, jbyteArray inOut, jint offset, jint len)
{
    int ok = 0;
    unsigned char iv_[16];
    (*env)->GetByteArrayRegion(env, iv, 0, 16, (jbyte*)iv_);
    unsigned char *inOut_ = (unsigned char*)(*env)->GetPrimitiveArrayCritical(env, inOut, NULL);
    if (!inOut_)
        goto exit;

    ok = EVP_CipherInit_ex(
                (EVP_CIPHER_CTX *) (intptr_t) ctx,
                NULL,
                NULL,
                NULL,
                iv_,
                -1);
    if(ok == 0)
        goto exit;

    int len_ = len;
    ok = EVP_CipherUpdate(
                (EVP_CIPHER_CTX *) (intptr_t) ctx,
                (unsigned char *) (inOut_ + offset), &len_,
                (unsigned char *) (inOut_ + offset), len);

exit:
    if (inOut_)
        (*env)->ReleasePrimitiveArrayCritical(env, inOut, inOut_, 0);

    return ok;
}
