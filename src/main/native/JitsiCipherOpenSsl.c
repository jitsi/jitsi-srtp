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
#include "org_jitsi_srtp_crypto_OpenSslAesCtrCipherSpi.h"
#include "org_jitsi_srtp_crypto_OpenSslAesGcmCipherSpi.h"
#include "org_jitsi_srtp_crypto_OpenSslAesEcbCipherSpi.h"


#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>

/* OpenSslAesCipherSpi: general OpenSSL AES cipher, applies to all modes. */

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesCipherSpi
 * Method:    EVP_CIPHER_CTX_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesCipherSpi_EVP_1CIPHER_1CTX_1new
  (JNIEnv *env, jobject thiz)
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
  (JNIEnv *env, jobject thiz, jlong ctx)
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
  (JNIEnv *env, jobject thiz, jlong ctx, jlong type, jbyteArray key, jbyteArray iv, jint enc)
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
  (JNIEnv *env, jobject thiz, jlong ctx, jbyteArray in, jint inOffset, jint len, jbyteArray out, jint outOffset)
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
    else if (out != NULL)
    {
        out_ = (unsigned char*)(*env)->GetPrimitiveArrayCritical(env, out, NULL);
        if (!out_)
            goto exit;
    }
    else
    {
        /* If out is null make sure outOffset is, too (AAD mode). */
        if (outOffset != 0)
            goto exit;
    }

    int outLen;
    ok = EVP_CipherUpdate(
                (EVP_CIPHER_CTX *) (intptr_t) ctx,
                (unsigned char *) (out_ + outOffset), &outLen,
                (unsigned char *) (in_ + inOffset), len);

exit:
    if (in != out && out != NULL && out_ != NULL)
        (*env)->ReleasePrimitiveArrayCritical(env, out, out_, 0);
    if (in_ != NULL)
        (*env)->ReleasePrimitiveArrayCritical(env, in, in_, 0);

    return ok;
}


/* OpenSslAesCtrCipherSpi: OpenSSL AES-CTR mode. */

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesCtrCipherSpi
 * Method:    EVP_aes_128_ctr
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesCtrCipherSpi_EVP_1aes_1128_1ctr
  (JNIEnv *env, jclass clazz)
{
    return (jlong) (intptr_t) EVP_aes_128_ctr();
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesCtrCipherSpi
 * Method:    EVP_aes_192_ctr
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesCtrCipherSpi_EVP_1aes_1192_1ctr
  (JNIEnv *env, jclass clazz)
{
    return (jlong) (intptr_t) EVP_aes_192_ctr();
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesCtrCipherSpi
 * Method:    EVP_aes_256_ctr
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesCtrCipherSpi_EVP_1aes_1256_1ctr
  (JNIEnv *env, jclass clazz)
{
    return (jlong) (intptr_t) EVP_aes_256_ctr();
}

/* OpenSslAesGcmCipherSpi: OpenSSL AES-GCM mode. */

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesGcmCipherSpi
 * Method:    EVP_aes_128_gcm
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesGcmCipherSpi_EVP_1aes_1128_1gcm
  (JNIEnv *env, jclass clazz)
{
    return (jlong) (intptr_t) EVP_aes_128_gcm();
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesGcmCipherSpi
 * Method:    EVP_aes_192_gcm
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesGcmCipherSpi_EVP_1aes_1192_1gcm
  (JNIEnv *env, jclass clazz)
{
    return (jlong) (intptr_t) EVP_aes_192_gcm();
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesGcmCipherSpi
 * Method:    EVP_aes_256_gcm
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesGcmCipherSpi_EVP_1aes_1256_1gcm
  (JNIEnv *env, jclass clazz)
{
    return (jlong) (intptr_t) EVP_aes_256_gcm();
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesGcmCipherSpi
 * Method:    EVP_CipherFinal
 * Signature: (J[BI)Z
 */
JNIEXPORT jboolean JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesGcmCipherSpi_EVP_1CipherFinal
  (JNIEnv * env, jclass clazz, jlong ctx, jbyteArray out, jint offset)
{
    int ok = 0;

    unsigned char *out_ = (unsigned char*)(*env)->GetPrimitiveArrayCritical(env, out, NULL);
    if (!out_)
        goto exit;

    int outLen;
    ok = EVP_CipherFinal(
                (EVP_CIPHER_CTX *) (intptr_t) ctx,
                (unsigned char *) (out_ + offset), &outLen);

exit:
    if (out_ != NULL)
        (*env)->ReleasePrimitiveArrayCritical(env, out, out_, 0);

    return ok;
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesGcmCipherSpi
 * Method:    CipherSetIVLen
 * Signature: (JI)Z
 */
JNIEXPORT jboolean JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesGcmCipherSpi_CipherSetIVLen
  (JNIEnv *env, jclass clazz, jlong ctx, jint ivLen)
{
    int ok = 0;

    ok = EVP_CIPHER_CTX_ctrl(
                (EVP_CIPHER_CTX *) (intptr_t) ctx,
                EVP_CTRL_GCM_SET_IVLEN,
                ivLen,
                NULL);

    return ok;
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesGcmCipherSpi
 * Method:    CipherSetTag
 * Signature: (J[BII)Z
 */
JNIEXPORT jboolean JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesGcmCipherSpi_CipherSetTag
  (JNIEnv *env, jclass clazz, jlong ctx, jbyteArray tag, jint offset, jint taglen)
{
    int ok = 0;

    unsigned char *tag_ = (unsigned char*)(*env)->GetPrimitiveArrayCritical(env, tag, NULL);
    if (!tag_)
        goto exit;

    ok = EVP_CIPHER_CTX_ctrl(
                (EVP_CIPHER_CTX *) (intptr_t) ctx,
                EVP_CTRL_GCM_SET_TAG,
                taglen,
                (unsigned char *) (tag_ + offset));

exit:
    if (tag_ != NULL)
        (*env)->ReleasePrimitiveArrayCritical(env, tag, tag_, 0);

    return ok;
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesGcmCipherSpi
 * Method:    CipherGetTag
 * Signature: (J[BII)Z
 */
JNIEXPORT jboolean JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesGcmCipherSpi_CipherGetTag
  (JNIEnv *env, jclass clazz, jlong ctx, jbyteArray tag, jint offset, jint taglen)
{
    int ok = 0;

    unsigned char *tag_ = (unsigned char*)(*env)->GetPrimitiveArrayCritical(env, tag, NULL);
    if (!tag_)
        goto exit;

    ok = EVP_CIPHER_CTX_ctrl(
                (EVP_CIPHER_CTX *) (intptr_t) ctx,
                EVP_CTRL_GCM_GET_TAG,
                taglen,
                (unsigned char *) (tag_ + offset));

exit:
    if (tag_ != NULL)
        (*env)->ReleasePrimitiveArrayCritical(env, tag, tag_, 0);

    return ok;
}


/* OpenSslAesEcbCipherSpi: OpenSSL AES-ECB mode. */

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesEcbCipherSpi
 * Method:    EVP_aes_128_ecb
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesEcbCipherSpi_EVP_1aes_1128_1ecb
  (JNIEnv *env, jclass clazz)
{
    return (jlong) (intptr_t) EVP_aes_128_ecb();
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesEcbCipherSpi
 * Method:    EVP_aes_192_ecb
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesEcbCipherSpi_EVP_1aes_1192_1ecb
  (JNIEnv *env, jclass clazz)
{
    return (jlong) (intptr_t) EVP_aes_192_ecb();
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesEcbCipherSpi
 * Method:    EVP_aes_256_ecb
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesEcbCipherSpi_EVP_1aes_1256_1ecb
  (JNIEnv *env, jclass clazz)
{
    return (jlong) (intptr_t) EVP_aes_256_ecb();
}
