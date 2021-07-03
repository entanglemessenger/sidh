package org.pqcrypto.sidh;

import junit.framework.TestCase;
import android.util.Log;
import static org.junit.Assert.*;

public class NativeSIDHProviderTest extends TestCase {
    public static final NativeSIDHProvider sidh = new NativeSIDHProvider();

    public void testCreateProvider() {
        NativeSIDHProvider sidh = new NativeSIDHProvider();
    }

    public void testAsymmetric() {
        long startTime, endTime;

        NativeSIDHProvider sidh = new NativeSIDHProvider();

        byte [] alice_privKeyA = sidh.generatePrivateKeyA();
        byte [] alice_pubKeyA = sidh.generatePublicKeyA(alice_privKeyA);

        byte [] bob_privKeyB = sidh.generatePrivateKeyB();
        byte [] bob_pubKeyB = sidh.generatePublicKeyB(bob_privKeyB);

        byte [] alice_secretKey = sidh.calculateAgreementA(alice_privKeyA, bob_pubKeyB);
        byte [] bob_secretKey = sidh.calculateAgreementB(bob_privKeyB, alice_pubKeyA);

        assertArrayEquals(alice_secretKey, bob_secretKey);
    }

    public void testTimeKeyGeneration() {
        long startTime, endTime;

        Log.d("TEST-FOO", "--START--");

        startTime = System.currentTimeMillis();
        byte [] alice_privKeyA = sidh.generatePrivateKeyA();
        byte [] alice_privKeyB = sidh.generatePrivateKeyB();
        byte [] alice_pubKeyA = sidh.generatePublicKeyA(alice_privKeyA);
        byte [] alice_pubKeyB = sidh.generatePublicKeyB(alice_privKeyB);

        byte [] bob_privKeyA = sidh.generatePrivateKeyA();
        byte [] bob_privKeyB = sidh.generatePrivateKeyB();
        byte [] bob_pubKeyA = sidh.generatePublicKeyA(bob_privKeyA);
        byte [] bob_pubKeyB = sidh.generatePublicKeyB(bob_privKeyB);
        endTime = System.currentTimeMillis();

        System.out.println("generateKeyPair() :: " + (endTime - startTime)/2.0 + " milliseconds");
        Log.d("TEST-FOO", "generateKeyPair() :: " + (endTime - startTime)/2.0 + " milliseconds");

        startTime = System.currentTimeMillis();
        byte [] alice_secretKey1 = sidh.calculateAgreementA(alice_privKeyA, bob_pubKeyB);
        byte [] alice_secretKey2 = sidh.calculateAgreementB(alice_privKeyB, bob_pubKeyA);
        byte [] alice_secretKey = new byte[alice_secretKey1.length];
        for(int i=0; i<alice_secretKey1.length; i++) {
            alice_secretKey[i] = (byte) (alice_secretKey1[i] ^ alice_secretKey2[i]);
        }

        byte [] bob_secretKey1 = sidh.calculateAgreementA(bob_privKeyA, alice_pubKeyB);
        byte [] bob_secretKey2 = sidh.calculateAgreementB(bob_privKeyB, alice_pubKeyA);
        byte [] bob_secretKey = new byte[bob_secretKey1.length];
        for(int i=0; i<bob_secretKey1.length; i++) {
            bob_secretKey[i] = (byte) (bob_secretKey1[i] ^ bob_secretKey2[i]);
        }
        endTime = System.currentTimeMillis();

        System.out.println("calculateAgreement() :: " + (endTime - startTime)/2.0 + " milliseconds");
        Log.d("TEST-FOO", "calculateAgreement() :: " + (endTime - startTime)/2.0 + " milliseconds");

        assertArrayEquals(alice_secretKey, bob_secretKey);
    }
}