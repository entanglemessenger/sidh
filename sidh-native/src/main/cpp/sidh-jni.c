#include <string.h>
#include <stdint.h>

#include <jni.h>


JNIEXPORT jbyteArray JNICALL Java_org_pqcrypto_sidh_NativeSIDHProvider_generatePrivateKeyA
        (JNIEnv *env, jobject obj)
{
    jbyteArray privateKey       = (*env)->NewByteArray(env, SIDH_SECRETKEYBYTES);
    uint8_t* privateKeyBytes = (uint8_t*)(*env)->GetByteArrayElements(env, privateKey, 0);

    random_mod_order_A(privateKeyBytes);

    (*env)->ReleaseByteArrayElements(env, privateKey, (jbyte *)privateKeyBytes, 0);

    return privateKey;
}

JNIEXPORT jbyteArray JNICALL Java_org_pqcrypto_sidh_NativeSIDHProvider_generatePrivateKeyB
        (JNIEnv *env, jobject obj)
{
    jbyteArray privateKey       = (*env)->NewByteArray(env, SIDH_SECRETKEYBYTES);
    uint8_t* privateKeyBytes = (uint8_t*)(*env)->GetByteArrayElements(env, privateKey, 0);

    random_mod_order_B(privateKeyBytes);

    (*env)->ReleaseByteArrayElements(env, privateKey, (jbyte *)privateKeyBytes, 0);

    return privateKey;
}

JNIEXPORT jbyteArray JNICALL Java_org_pqcrypto_sidh_NativeSIDHProvider_generatePublicKeyA
        (JNIEnv *env, jobject obj, jbyteArray privateKey)
{
    jbyteArray publicKey       = (*env)->NewByteArray(env, SIDH_PUBLICKEYBYTES);
    uint8_t*   publicKeyBytes  = (uint8_t*)(*env)->GetByteArrayElements(env, publicKey, 0);
    uint8_t*   privateKeyBytes = (uint8_t*)(*env)->GetByteArrayElements(env, privateKey, 0);

    EphemeralKeyGeneration_A(privateKeyBytes, publicKeyBytes);

    (*env)->ReleaseByteArrayElements(env, publicKey, (jbyte *)publicKeyBytes, 0);
    (*env)->ReleaseByteArrayElements(env, privateKey, (jbyte *)privateKeyBytes, 0);

    return publicKey;
}

JNIEXPORT jbyteArray JNICALL Java_org_pqcrypto_sidh_NativeSIDHProvider_generatePublicKeyB
        (JNIEnv *env, jobject obj, jbyteArray privateKey)
{
    jbyteArray publicKey       = (*env)->NewByteArray(env, SIDH_PUBLICKEYBYTES);
    uint8_t*   publicKeyBytes  = (uint8_t*)(*env)->GetByteArrayElements(env, publicKey, 0);
    uint8_t*   privateKeyBytes = (uint8_t*)(*env)->GetByteArrayElements(env, privateKey, 0);

    EphemeralKeyGeneration_B(privateKeyBytes, publicKeyBytes);

    (*env)->ReleaseByteArrayElements(env, publicKey, (jbyte *)publicKeyBytes, 0);
    (*env)->ReleaseByteArrayElements(env, privateKey, (jbyte *)privateKeyBytes, 0);

    return publicKey;
}

JNIEXPORT jbyteArray JNICALL Java_org_pqcrypto_sidh_NativeSIDHProvider_calculateAgreementA
        (JNIEnv *env, jobject obj, jbyteArray privateKey, jbyteArray publicKey)
{
    jbyteArray sharedKey       = (*env)->NewByteArray(env, SIDH_BYTES);
    uint8_t*   sharedKeyBytes  = (uint8_t*)(*env)->GetByteArrayElements(env, sharedKey, 0);
    uint8_t*   privateKeyBytes = (uint8_t*)(*env)->GetByteArrayElements(env, privateKey, 0);
    uint8_t*   publicKeyBytes  = (uint8_t*)(*env)->GetByteArrayElements(env, publicKey, 0);

    EphemeralSecretAgreement_A(privateKeyBytes, publicKeyBytes, sharedKeyBytes);

    (*env)->ReleaseByteArrayElements(env, sharedKey, (jbyte *)sharedKeyBytes, 0);
    (*env)->ReleaseByteArrayElements(env, publicKey, (jbyte *)publicKeyBytes, 0);
    (*env)->ReleaseByteArrayElements(env, privateKey, (jbyte *)privateKeyBytes, 0);

    return sharedKey;
}

JNIEXPORT jbyteArray JNICALL Java_org_pqcrypto_sidh_NativeSIDHProvider_calculateAgreementB
        (JNIEnv *env, jobject obj, jbyteArray privateKey, jbyteArray publicKey)
{
    jbyteArray sharedKey       = (*env)->NewByteArray(env, SIDH_BYTES);
    uint8_t*   sharedKeyBytes  = (uint8_t*)(*env)->GetByteArrayElements(env, sharedKey, 0);
    uint8_t*   privateKeyBytes = (uint8_t*)(*env)->GetByteArrayElements(env, privateKey, 0);
    uint8_t*   publicKeyBytes  = (uint8_t*)(*env)->GetByteArrayElements(env, publicKey, 0);

    EphemeralSecretAgreement_B(privateKeyBytes, publicKeyBytes, sharedKeyBytes);

    (*env)->ReleaseByteArrayElements(env, sharedKey, (jbyte *)sharedKeyBytes, 0);
    (*env)->ReleaseByteArrayElements(env, publicKey, (jbyte *)publicKeyBytes, 0);
    (*env)->ReleaseByteArrayElements(env, privateKey, (jbyte *)privateKeyBytes, 0);

    return sharedKey;
}

JNIEXPORT jboolean JNICALL Java_org_pqcrypto_sidh_NativeSIDHProvider_smokeCheck
        (JNIEnv *env, jobject obj, jint dummy)
{
    return 1;
}
