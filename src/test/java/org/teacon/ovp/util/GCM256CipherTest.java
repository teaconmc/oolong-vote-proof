package org.teacon.ovp.util;

import com.google.common.io.Resources;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.random.RandomGenerator;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class GCM256CipherTest {
    private static final List<Vector> VECTORS;

    static {
        var vectors = "vectors/gcm256/gcm256cipher-test-vectors.txt";
        try {
            var lines = Resources.readLines(Resources.getResource(vectors), UTF_8);
            VECTORS = lines.stream()
                    .filter(l -> !l.isBlank())
                    .filter(l -> !l.startsWith("#"))
                    .map(Vector::parse)
                    .toList();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load test vectors", e);
        }
    }

    @Test
    void encrypt_produces_expected_raw_and_decrypt_roundTrips_for_testVectors() {
        for (var vector : VECTORS) {
            var plain = ByteBufUtil.decodeHexDump(vector.plainHex);
            var key = ByteBufUtil.decodeHexDump(vector.keyHex);
            var expectedRaw = ByteBufUtil.decodeHexDump(vector.cipherHex);

            // Nonce is the first 12 bytes of the raw ciphertext.
            var nonceHex = vector.cipherHex.substring(0, 12 * 2);
            var entropy = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(nonceHex));
            // Delegate created exactly like ShortMnemonicTest; override nextBytes so AES-GCM nonce
            // is filled from the 12-byte prefix deterministically (without depending on JDK's
            // default RandomGenerator.nextBytes implementation details).
            var delegate = (RandomGenerator) entropy::readLongLE;
            RandomGenerator rng = new RandomGenerator() {
                @Override
                public long nextLong() {
                    return delegate.nextLong();
                }

                @Override
                public void nextBytes(byte[] bytes) {
                    entropy.readBytes(bytes);
                }
            };

            var cipher = new GCM256Cipher(rng, plain, key);
            assertArrayEquals(expectedRaw, cipher.raw());

            var parsed = new GCM256Cipher(expectedRaw);
            assertArrayEquals(plain, parsed.decrypt(key));
        }
    }

    private record Vector(String plainHex, String keyHex, String cipherHex) {
        private static Vector parse(String line) {
            var parts = line.split(":", -1);
            if (parts.length != 3) {
                throw new IllegalArgumentException("Unexpected vector format: " + line);
            }
            return new Vector(parts[0].strip(), parts[1].strip(), parts[2].strip());
        }
    }
}

