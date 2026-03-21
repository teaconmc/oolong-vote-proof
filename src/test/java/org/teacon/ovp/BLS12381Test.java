package org.teacon.ovp;

import com.google.common.io.BaseEncoding;
import com.google.common.io.Resources;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BLS12381Test {
    private static final List<G1Vector> G1_VECTORS;
    private static final List<ScalarVector> SCALAR_VECTORS;

    static {
        var g1 = "vectors/bls12-381/bls12-381-g1-test-vectors.txt";
        var scalar = "vectors/bls12-381/bls12-381-scalar-test-vectors.txt";
        try {
            var g1Lines = Resources.readLines(Resources.getResource(g1), UTF_8);
            var scalarLines = Resources.readLines(Resources.getResource(scalar), UTF_8);
            G1_VECTORS = g1Lines.stream().filter(l -> !l.isBlank()).map(G1Vector::parse).toList();
            SCALAR_VECTORS = scalarLines.stream().filter(l -> !l.isBlank()).map(ScalarVector::parse).toList();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load vectors from " + g1, e);
        }
    }

    @Test
    void testScalarVectors() {
        var scalar = Unpooled.buffer();
        for (var vector : SCALAR_VECTORS) {
            var field = BLS12381.hashToScalar(vector.okmAscii.slice(), vector.okmAscii.readableBytes());
            BLS12381.fieldToSecretKey(field, scalar.clear());
            assertEquals(vector.expectedScalarHex, G1Vector.HEX.encode(ByteBufUtil.getBytes(scalar)));
        }
    }

    @Test
    void coreSignAndVerifyG1Vectors() {
        var signature = Unpooled.buffer();
        var pubKey = Unpooled.buffer();
        for (var vector : G1_VECTORS) {
            var secret = BLS12381.secretKeyToField(vector.privateKey.slice());
            BLS12381.coreSign(secret, vector.message.slice(), vector.message.readableBytes(), signature.clear());
            assertEquals(vector.expectedSignatureHex, G1Vector.HEX.encode(ByteBufUtil.getBytes(signature)));
            BLS12381.skToPk(secret, pubKey.clear());
            assertTrue(BLS12381.coreVerify(pubKey, vector.message.slice(), vector.message.readableBytes(), signature));
        }
    }

    private record G1Vector(ByteBuf privateKey, ByteBuf message, String expectedSignatureHex) {
        private static final BaseEncoding HEX = BaseEncoding.base16().lowerCase();

        private static G1Vector parse(String line) {
            var parts = line.split(":", -1);
            if (parts.length != 3) {
                throw new IllegalArgumentException("Unexpected vector format: " + line);
            }
            var privateKey = Unpooled.wrappedBuffer(HEX.decode(parts[0])).asReadOnly();
            var message = Unpooled.wrappedBuffer(HEX.decode(parts[1])).asReadOnly();
            return new G1Vector(privateKey, message, parts[2]);
        }
    }

    private record ScalarVector(ByteBuf okmAscii, String expectedScalarHex) {
        private static final BaseEncoding HEX = BaseEncoding.base16().lowerCase();

        private static ScalarVector parse(String line) {
            var parts = line.split(":", -1);
            if (parts.length != 2) {
                throw new IllegalArgumentException("Unexpected vector format: " + line);
            }
            var okmAscii = Unpooled.wrappedBuffer(parts[0].getBytes(StandardCharsets.US_ASCII)).asReadOnly();
            return new ScalarVector(okmAscii, parts[1]);
        }
    }
}
