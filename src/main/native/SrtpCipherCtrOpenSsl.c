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
 * Class:     org_jitsi_srtp_crypto_OpenSslAesCipherSpi
 * Method:    EVP_aes_128_ctr
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesCipherSpi_EVP_1aes_1128_1ctr
  (JNIEnv *env, jclass clazz)
{
    return (jlong) (intptr_t) EVP_aes_128_ctr();
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesCipherSpi
 * Method:    EVP_aes_192_ctr
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesCipherSpi_EVP_1aes_1192_1ctr
  (JNIEnv *env, jclass clazz)
{
    return (jlong) (intptr_t) EVP_aes_192_ctr();
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesCipherSpi
 * Method:    EVP_aes_256_ctr
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesCipherSpi_EVP_1aes_1256_1ctr
  (JNIEnv *env, jclass clazz)
{
    return (jlong) (intptr_t) EVP_aes_256_ctr();
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesCipherSpi
 * Method:    EVP_CIPHER_CTX_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesCipherSpi_EVP_1CIPHER_1CTX_1new
  (JNIEnv *env, jclass clazz)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    return (jlong) (intptr_t) ctx;
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesCipherSpi
 * Method:    EVP_CIPHER_CTX_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesCipherSpi_EVP_1CIPHER_1CTX_1free
  (JNIEnv *env, jclass clazz, jlong ctx)
{
    if (ctx) {
        EVP_CIPHER_CTX *ctx_ = (EVP_CIPHER_CTX *) (intptr_t) ctx;
        EVP_CIPHER_CTX_free(ctx_);
    }
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesCipherSpi
 * Method:    EVP_CipherInit
 * Signature: (JJ[B[BI)Z
 */
JNIEXPORT jboolean JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesCipherSpi_EVP_1CipherInit
  (JNIEnv *env, jclass clazz, jlong ctx, jlong type, jbyteArray key, jbyteArray iv, jint enc)
{
    jboolean r = JNI_FALSE;
    unsigned char *key_ = NULL, *iv_ = NULL;
    if (key != NULL)
    {
        key_ = (unsigned char*)(*env)->GetPrimitiveArrayCritical(env, key, NULL);
        if (key_ == NULL)
            goto exit;
    }

    if (iv != NULL)
    {
        iv_ = (unsigned char*)(*env)->GetPrimitiveArrayCritical(env, iv, NULL);
        if (iv_ == NULL)
            goto exit;
    }

    r = EVP_CipherInit_ex((EVP_CIPHER_CTX *) (intptr_t) ctx, (const EVP_CIPHER *) (intptr_t) type, NULL, key_, iv_, enc);

exit:
    if (key_ != NULL)
        (*env)->ReleasePrimitiveArrayCritical(env, key, key_, 0);
    if (iv_ != NULL)
        (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_, 0);
    return r;
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesCipherSpi
 * Method:    EVP_CipherUpdate
 * Signature: (J[BII)Z
 */
JNIEXPORT jboolean JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesCipherSpi_EVP_1CipherUpdate
  (JNIEnv *env, jclass clazz, jlong ctx, jbyteArray in, jint inOffset, jint len, jbyteArray out, jint outOffset)
{
    int ok = 0;
    unsigned char *in_ = (unsigned char*)(*env)->GetPrimitiveArrayCritical(env, in, NULL);
    unsigned char *out_ = NULL;
    if (!in_)
        goto exit;
    if (in == out)
    {
        out_ = in_;
    }
    else
    {
        out_ = (unsigned char*)(*env)->GetPrimitiveArrayCritical(env, out, NULL);
        if (!out_)
            goto exit;
    }

    int len_ = len;
    ok = EVP_CipherUpdate(
                (EVP_CIPHER_CTX *) (intptr_t) ctx,
                (unsigned char *) (in_ + inOffset), &len_,
                (unsigned char *) (out_ + outOffset), len);

exit:
    if (out_ != NULL && in != out)
        (*env)->ReleasePrimitiveArrayCritical(env, out, out_, 0);
    if (in_ != NULL)
        (*env)->ReleasePrimitiveArrayCritical(env, in, in_, 0);

    return ok;
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesCipherSpi
 * Method:    EVP_CipherFinal
 * Signature: (J[BI)Z
 */
JNIEXPORT jboolean JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesCipherSpi_EVP_1CipherFinal
  (JNIEnv * env, jclass clazz, jlong ctx, jbyteArray out, jint offset)
{
    int ok = 0;

    unsigned char *out_ = (unsigned char*)(*env)->GetPrimitiveArrayCritical(env, out, NULL);
    if (!out_)
        goto exit;

    int len_ = 0;
    ok = EVP_CipherFinal(
                (EVP_CIPHER_CTX *) (intptr_t) ctx,
                (unsigned char *) (out_ + offset), &len_);

exit:
    if (out_ != NULL)
        (*env)->ReleasePrimitiveArrayCritical(env, out, out_, 0);

    return ok;
}
