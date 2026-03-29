package org.teacon.ovp.util;

import com.google.common.base.Preconditions;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.random.RandomGenerator;

public class GCM256Cipher {
    private static final int KEY_SIZE = 32;
    private static final int NONCE_SIZE = 12;
    private static final int TAG_SIZE = 16;
    private static final int PLAIN_SIZE = 32;
    private static final int RAW_SIZE = NONCE_SIZE + PLAIN_SIZE + TAG_SIZE;

    private final byte[] data;

    public GCM256Cipher(RandomGenerator randomGenerator, byte[] plain, byte[] key) {
        Preconditions.checkArgument(plain.length == PLAIN_SIZE, "Plain text must be 32 bytes");
        Preconditions.checkArgument(key.length == KEY_SIZE, "Key must be 32 bytes");

        try {
            var nonce = new byte[NONCE_SIZE];
            randomGenerator.nextBytes(nonce);

            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            var keySpec = new SecretKeySpec(key, "AES");
            var gcmSpec = new GCMParameterSpec(TAG_SIZE * 8, nonce);

            this.data = Arrays.copyOf(nonce, RAW_SIZE);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            cipher.doFinal(plain, 0, PLAIN_SIZE, this.data, NONCE_SIZE);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public GCM256Cipher(byte[] data) {
        Preconditions.checkArgument(data.length == RAW_SIZE, "Data must be 60 bytes");
        this.data = data.clone();
    }

    public byte[] decrypt(byte[] key) {
        Preconditions.checkArgument(key.length == KEY_SIZE, "Key must be 32 bytes");
        var plain = new byte[PLAIN_SIZE];

        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            var keySpec = new SecretKeySpec(key, "AES");
            var gcmSpec = new GCMParameterSpec(TAG_SIZE * 8, this.data, 0, NONCE_SIZE);

            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            cipher.doFinal(this.data, NONCE_SIZE, this.data.length - NONCE_SIZE, plain, 0);
        } catch (Exception e) {
            throw new IllegalArgumentException("Decryption failed (possible tampering or wrong key)", e);
        }

        return plain;
    }

    public byte[] raw() {
        return this.data.clone();
    }
}
