package org.teacon.ovp.util;

import com.google.common.io.Resources;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.random.RandomGenerator;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ShortMnemonicTest {
    private static final List<Vector> VECTORS;

    static {
        var vectors = "vectors/bip39/bip39-128bit-test-vectors.txt";
        try {
            var lines = Resources.readLines(Resources.getResource(vectors), UTF_8);
            VECTORS = lines.stream().filter(l -> !l.isBlank()).map(Vector::parse).toList();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load test vectors", e);
        }
    }

    @Test
    void shortMnemonic_and_pbkdf2_match_BIP39_testVectors_for_128bit_entropy() {
        var out = Unpooled.buffer(64);
        for (var vector : VECTORS) {
            var entropy = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(vector.entropyHex));
            var rng = (RandomGenerator) entropy::readLongLE;
            var mnemonic = new ShortMnemonic(rng);
            assertEquals(0, entropy.readableBytes());
            assertEquals(vector.mnemonic, new String(mnemonic.chars()));
            BLS12381.pbkdf2(mnemonic.chars(), "mnemonicTREZOR", out.clear(), 64);
            assertEquals(vector.seedHex, ByteBufUtil.hexDump(out));
        }
    }

    private record Vector(String entropyHex, String mnemonic, String seedHex) {
        private static Vector parse(String line) {
            var parts = line.split(":", -1);
            if (parts.length != 3) {
                throw new IllegalArgumentException("Unexpected vector format: " + line);
            }
            return new Vector(parts[0].strip(), parts[1].strip(), parts[2].strip());
        }
    }
}
