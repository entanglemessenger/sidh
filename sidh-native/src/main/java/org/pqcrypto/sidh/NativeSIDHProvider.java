package org.pqcrypto.sidh;

public class NativeSIDHProvider implements SIDHProvider {

    private static boolean   libraryPresent         = false;
    private static Throwable libraryFailedException = null;

    static {
        try {
            System.loadLibrary("sidh-lib");
            libraryPresent = true;
        } catch (UnsatisfiedLinkError | SecurityException e) {
            libraryPresent         = false;
            libraryFailedException = e;
        }
    }

    public NativeSIDHProvider() throws NoSuchProviderException {
        if (!libraryPresent) throw new NoSuchProviderException(libraryFailedException);

        try {
            smokeCheck(31337);
        } catch (UnsatisfiedLinkError ule) {
            throw new NoSuchProviderException(ule);
        }
    }

    @Override
    public boolean isNative() {
        return true;
    }

    @Override
    public native byte[] generatePrivateKeyA();

    @Override
    public native byte[] generatePrivateKeyB();

    @Override
    public native byte[] calculateAgreementA(byte[] ourPrivate, byte[] theirPublic);

    @Override
    public native byte[] calculateAgreementB(byte[] ourPrivate, byte[] theirPublic);

    @Override
    public native byte[] generatePublicKeyA(byte[] privateKeyA);

    @Override
    public native byte[] generatePublicKeyB(byte[] privateKeyB);


    private native boolean smokeCheck(int dummy);
}
