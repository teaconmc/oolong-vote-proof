package org.teacon.ovp;

import com.google.common.io.BaseEncoding;
import com.google.common.io.Resources;
import org.junit.jupiter.api.Test;
import org.teacon.ovp.miracl.core.BLS12381.BLS;

import java.io.IOException;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BLS12381Test {
    private static final List<TestVector> G1_VECTORS;

    static {
        var resource = "bls12-381-g1-test-vectors.txt";
        try {
            var lines = Resources.readLines(Resources.getResource(resource), UTF_8);
            G1_VECTORS = lines.stream().filter(line -> !line.isBlank()).map(TestVector::parse).toList();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load vectors from " + resource, e);
        }
    }

    @Test
    void coreSignAndVerifyG1Vectors() {
        for (var vector : G1_VECTORS) {
            var secret = BLS12381.secretKeyToField(vector.privateKey);
            var signature = BLS12381.coreSign(secret, vector.message);
            assertEquals(vector.expectedSignatureHex, TestVector.HEX.encode(signature));
            assertTrue(BLS12381.coreVerify(BLS12381.skToPk(secret), vector.message, signature));
        }
    }

    private record TestVector(byte[] privateKey, byte[] message, String expectedSignatureHex) {
        private static final BaseEncoding HEX = BaseEncoding.base16().lowerCase();

        private static TestVector parse(String line) {
            var parts = line.split(":", -1);
            if (parts.length != 3) {
                throw new IllegalArgumentException("Unexpected vector format: " + line);
            }
            return new TestVector(HEX.decode(parts[0]), HEX.decode(parts[1]), parts[2]);
        }
    }
}
