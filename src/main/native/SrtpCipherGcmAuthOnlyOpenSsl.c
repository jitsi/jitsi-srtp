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

#include <org_jitsi_srtp_crypto_OpenSslAesGcmAuthOnlyCipherSpi.h>

#include <openssl/modes.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>


#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

typedef struct {
    EVP_CIPHER_CTX* cipher;
    GCM128_CONTEXT* gcm;
} AES_GCM_CONTEXT;


/* Encrypt one block with an EVP_CIPHER_CTX, with a function signature
 * compatible with block128_f */
static void EVP_encrypt(const unsigned char in[16],
    unsigned char out[16], const void *ctx)
{
    EVP_CIPHER_CTX* ctx_ = (EVP_CIPHER_CTX*)ctx;
    int len = 16;
    EVP_EncryptUpdate(ctx_, out, &len, in, len);
    assert(len == 16);
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesGcmAuthOnlyCipherSpi
 * Method:    CRYPTO_gcm128_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesGcmAuthOnlyCipherSpi_CRYPTO_1gcm128_1new
  (JNIEnv *env, jobject thiz)
{
    AES_GCM_CONTEXT* ctx = malloc(sizeof(AES_GCM_CONTEXT));
    if (ctx == NULL)
    {
        goto fail;
    }

    ctx->cipher = EVP_CIPHER_CTX_new();
    if (ctx->cipher == NULL)
    {
        goto fail;
    }

    ctx->gcm = NULL;

    return (jlong)(uintptr_t)ctx;

fail:
    if (ctx != NULL)
    {
        if (ctx->cipher != NULL)
        {
            EVP_CIPHER_CTX_free(ctx->cipher);
        }
        free(ctx);
    }

    return 0;
}



/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesGcmAuthOnlyCipherSpi
 * Method:    CRYPTO_gcm128_release
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesGcmAuthOnlyCipherSpi_CRYPTO_1gcm128_1release
  (JNIEnv *env, jobject thiz, jlong ctx)
{
    if (ctx != 0)
    {
        AES_GCM_CONTEXT* ctx_ = (AES_GCM_CONTEXT*) (uintptr_t) ctx;
        if (ctx_->gcm != NULL)
        {
            CRYPTO_gcm128_release(ctx_->gcm);
        }
        EVP_CIPHER_CTX_free(ctx_->cipher);
        free(ctx_);
    }
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesGcmAuthOnlyCipherSpi
 * Method:    CRYPTO_gcm128_init
 * Signature: (J[B)Z
 */
JNIEXPORT jboolean JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesGcmAuthOnlyCipherSpi_CRYPTO_1gcm128_1init
  (JNIEnv *env, jobject thiz, jlong ctx, jbyteArray key)
{
    jboolean r = JNI_FALSE;
    AES_GCM_CONTEXT* ctx_ = (AES_GCM_CONTEXT*)ctx;
    size_t keylen = (size_t)(*env)->GetArrayLength(env, key);
    unsigned char *key_ = (unsigned char*)(*env)->GetPrimitiveArrayCritical(env, key, NULL);
    if (key_ == NULL)
        goto exit;

    const EVP_CIPHER* cipher;
    switch(keylen)
    {
    case 16:
        cipher = EVP_aes_128_ecb();
        break;
    case 24:
        cipher = EVP_aes_192_ecb();
        break;
    case 32:
        cipher = EVP_aes_256_ecb();
        break;
    default:
        goto exit;
    }

    r = EVP_EncryptInit_ex(ctx_->cipher, cipher, NULL, key_, NULL);
    if (!r)
    {
        goto exit;
    }

    ctx_->gcm = CRYPTO_gcm128_new(ctx_->cipher, EVP_encrypt);
    r = (ctx_->gcm != NULL);

exit:
    if (key_ != NULL)
        (*env)->ReleasePrimitiveArrayCritical(env, key, key_, 0);

    return r;
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesGcmAuthOnlyCipherSpi
 * Method:    CRYPTO_gcm128_setiv
 * Signature: (J[BI)Z
 */
JNIEXPORT jboolean JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesGcmAuthOnlyCipherSpi_CRYPTO_1gcm128_1setiv
  (JNIEnv *env, jobject thiz, jlong ctx, jbyteArray iv, jint len)
{
    jboolean ok = JNI_FALSE;
    AES_GCM_CONTEXT* ctx_ = (AES_GCM_CONTEXT*)ctx;
    if (ctx_->gcm == NULL)
        return JNI_FALSE; /* Not initialized */
    unsigned char *iv_ = (unsigned char*)(*env)->GetPrimitiveArrayCritical(env, iv, NULL);
    if (iv_ == NULL)
        return JNI_FALSE;

    CRYPTO_gcm128_setiv(ctx_->gcm, iv_, len);
    ok = JNI_TRUE;

    (*env)->ReleasePrimitiveArrayCritical(env, iv, iv_, 0);
    return ok;
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesGcmAuthOnlyCipherSpi
 * Method:    CRYPTO_gcm128_aad
 * Signature: (J[BII)Z
 */
JNIEXPORT jboolean JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesGcmAuthOnlyCipherSpi_CRYPTO_1gcm128_1aad
  (JNIEnv *env, jobject thiz, jlong ctx, jbyteArray in, jint inOffset, jint len)
{
    jboolean ok = 0;
    AES_GCM_CONTEXT* ctx_ = (AES_GCM_CONTEXT*)ctx;
    if (ctx_->gcm == NULL)
        return JNI_FALSE; /* Not initialized */
    unsigned char *in_ = (unsigned char*)(*env)->GetPrimitiveArrayCritical(env, in, NULL);
    if (in_ == NULL)
        return JNI_FALSE;

    ok = (CRYPTO_gcm128_aad(ctx_->gcm, in_ + inOffset, len) == 0);

    (*env)->ReleasePrimitiveArrayCritical(env, in, in_, 0);

    return ok;
}

/* A null cipher, suitable for passing as ctr128_f. */
static void null_cipher(const unsigned char *in, unsigned char *out,
                          size_t blocks, const void *key,
                          const unsigned char ivec[16])
{
    return;
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesGcmAuthOnlyCipherSpi
 * Method:    CRYPTO_gcm128_decrypt
 * Signature: (J[BII)Z
 */
JNIEXPORT jboolean JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesGcmAuthOnlyCipherSpi_CRYPTO_1gcm128_1decrypt
  (JNIEnv *env, jobject thiz, jlong ctx, jbyteArray in, jint inOffset, jint len)
{
    jboolean ok = 0;
    AES_GCM_CONTEXT* ctx_ = (AES_GCM_CONTEXT*)ctx;
    if (ctx_->gcm == NULL)
        return JNI_FALSE; /* Not initialized */
    unsigned char *in_ = (unsigned char*)(*env)->GetPrimitiveArrayCritical(env, in, NULL);
    if (in_ == NULL)
        return JNI_FALSE;

    /* In order to do auth-without-decrypt with an OpenSSL GCM_CONTEXT, we call
     * int CRYPTO_gcm128_decrypt_ctr32 with a no-op stream cipher. */

    ok = (CRYPTO_gcm128_decrypt_ctr32(ctx_->gcm, in_ + inOffset,
        in_ + inOffset, len, null_cipher) == 0);

    (*env)->ReleasePrimitiveArrayCritical(env, in, in_, 0);

    return ok;
}

/*
 * Class:     org_jitsi_srtp_crypto_OpenSslAesGcmAuthOnlyCipherSpi
 * Method:    CRYPTO_gcm128_finish
 * Signature: (J[BII)Z
 */
JNIEXPORT jboolean JNICALL Java_org_jitsi_srtp_crypto_OpenSslAesGcmAuthOnlyCipherSpi_CRYPTO_1gcm128_1finish
  (JNIEnv * env, jobject thiz, jlong ctx, jbyteArray tag, jint tagOffset, jint tagLen)
{
    int ok = 0;
    AES_GCM_CONTEXT* ctx_ = (AES_GCM_CONTEXT*)ctx;
    if (ctx_->gcm == NULL)
        return JNI_FALSE; /* Not initialized */

    unsigned char *tag_ = (unsigned char*)(*env)->GetPrimitiveArrayCritical(env, tag, NULL);
    if (!tag_)
        return JNI_FALSE;

    ok = (CRYPTO_gcm128_finish(ctx_->gcm, tag_ + tagOffset, tagLen) == 0);

    (*env)->ReleasePrimitiveArrayCritical(env, tag, tag_, 0);

    return ok;
}
