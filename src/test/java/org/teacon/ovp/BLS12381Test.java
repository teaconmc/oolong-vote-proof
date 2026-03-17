package org.teacon.ovp;

import com.google.common.io.BaseEncoding;
import com.google.common.io.Resources;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BLS12381Test {
    private static final List<TestVector> G1_VECTORS;

    static {
        var resource = "vectors/bls12-381/bls12-381-g1-test-vectors.txt";
        try {
            var lines = Resources.readLines(Resources.getResource(resource), UTF_8);
            G1_VECTORS = lines.stream().filter(line -> !line.isBlank()).map(TestVector::parse).toList();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load vectors from " + resource, e);
        }
    }

    @Test
    void coreSignAndVerifyG1Vectors() {
        var signature = Unpooled.buffer();
        var pubKey = Unpooled.buffer();
        for (var vector : G1_VECTORS) {
            var secret = BLS12381.secretKeyToField(vector.privateKey);
            signature.readerIndex(0).writerIndex(0);
            BLS12381.coreSign(secret, vector.message, vector.message.readableBytes(), signature);
            assertEquals(vector.expectedSignatureHex, TestVector.HEX.encode(ByteBufUtil.getBytes(signature)));
            pubKey.readerIndex(0).writerIndex(0);
            BLS12381.skToPk(secret, pubKey);
            vector.message.readerIndex(0);
            assertTrue(BLS12381.coreVerify(pubKey, vector.message, vector.message.readableBytes(), signature));
        }
    }

    private record TestVector(ByteBuf privateKey, ByteBuf message, String expectedSignatureHex) {
        private static final BaseEncoding HEX = BaseEncoding.base16().lowerCase();

        private static TestVector parse(String line) {
            var parts = line.split(":", -1);
            if (parts.length != 3) {
                throw new IllegalArgumentException("Unexpected vector format: " + line);
            }
            var privateKey = Unpooled.wrappedBuffer(HEX.decode(parts[0])).asReadOnly();
            var message = Unpooled.wrappedBuffer(HEX.decode(parts[1])).asReadOnly();
            return new TestVector(privateKey, message, parts[2]);
        }
    }
}
