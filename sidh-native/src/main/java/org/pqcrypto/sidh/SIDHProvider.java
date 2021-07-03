package org.pqcrypto.sidh;

interface SIDHProvider {

    boolean isNative();
    byte[] calculateAgreementA(byte[] ourPrivate, byte[] theirPublic);
    byte[] calculateAgreementB(byte[] ourPrivate, byte[] theirPublic);
    byte[] generatePublicKeyA(byte[] privateKey);
    byte[] generatePublicKeyB(byte[] privateKey);
    byte[] generatePrivateKeyA();
    byte[] generatePrivateKeyB();
}
