/*
 * Copyright (C) 2026 TeaConMC <contact@teacon.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package org.teacon.ovp.util;

import com.google.common.io.Resources;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.random.RandomGenerator;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

class BLS12381Test {
    private static final List<G1Vector> G1_VECTORS;
    private static final List<ScalarVector> SCALAR_VECTORS;
    private static final List<FMAVector> FMA_VECTORS;

    static {
        var g1 = "vectors/bls12-381/bls12-381-g1-test-vectors.txt";
        var scalar = "vectors/bls12-381/bls12-381-scalar-test-vectors.txt";
        var fma = "vectors/bls12-381/bls12-381-fma-test-vectors.txt";
        try {
            var g1Lines = Resources.readLines(Resources.getResource(g1), UTF_8);
            var scalarLines = Resources.readLines(Resources.getResource(scalar), UTF_8);
            var fmaLines = Resources.readLines(Resources.getResource(fma), UTF_8);
            G1_VECTORS = g1Lines.stream().filter(l -> !l.isBlank()).map(G1Vector::parse).toList();
            SCALAR_VECTORS = scalarLines.stream().filter(l -> !l.isBlank()).map(ScalarVector::parse).toList();
            FMA_VECTORS = fmaLines.stream().filter(l -> !l.isBlank()).map(FMAVector::parse).toList();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load test vectors", e);
        }
    }

    @Test
    void hashToScalar_matches_scalar_testVectors() {
        var scalar = Unpooled.buffer();
        for (var vector : SCALAR_VECTORS) {
            var field = BLS12381.hashToScalar(vector.okmAscii.slice(), vector.okmAscii.readableBytes());
            BLS12381.fieldToBytes(field, scalar.clear());
            assertEquals(vector.expectedScalarHex, ByteBufUtil.hexDump(scalar));
        }
    }

    @Test
    void coreSign_produces_expected_signatures_and_coreVerify_accepts_g1_testVectors() {
        var signature = Unpooled.buffer();
        var pubKey = Unpooled.buffer();
        for (var vector : G1_VECTORS) {
            var secret = BLS12381.secretKeyToField(vector.privateKey.slice());
            BLS12381.coreSign(secret, vector.message.slice(), vector.message.readableBytes(), signature.clear());
            assertEquals(vector.expectedSignatureHex, ByteBufUtil.hexDump(signature));
            BLS12381.skToPk(secret, pubKey.clear());
            assertTrue(BLS12381.coreVerify(pubKey, vector.message.slice(), vector.message.readableBytes(), signature));
        }
    }

    @Test
    void randomToField_consumes_expected_entropy_and_matches_expected_scalars() {
        var entropyBytesHex = "fa967ca7b50eb138b49ea6dafaba2a6e9b4711309d5d7439780ac4239f34e61f49c45efe10a5a3b3f8589c" +
                "a62dc56dd5630d46820cba7ef4260945b4bb16f4c4a193753d2044df691bbcf093d3ba0d774fd0dbf55787db03f66a2889b4" +
                "09db4bbfb927bc772b71cd12a32d47289ace23b173f29b2a56df83e12e847e74fd1ba270498f1031ee619e222b0d93e9eccf" +
                "7544bf81575c4877a124a67c9ce66264731b0ffeac1dbdd2f7055a0e453a2c32e72026f81716169c5446604880bf59d91400" +
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "000000000000000000233a56cb736a9eda91e6d1829d76a75f570f622ea42f2e9728113e1c969893e37f244cc29ae4810ebd" +
                "591f9fc8af268516fbe2546f557bd5702e90644d355d8148d0655084726465bc0ddbe4d0a89362a7d4801de0500a649955b6" +
                "e899e6ce33c534767b8ec37e8cd7a6971e7bc44ac7fba50064e0ba96abec325cabbb760ef86d0c41ffada8f12ddb4d853744" +
                "8f85319503dce8f4c489d1027f73050c85e9bb8d30006d6ca575c675fb26063c928adc7702d12f7063064d644f84abd9c5e0" +
                "756ef9aca44696e5efb5c2de4a9fcab4f240c2de3b94b39d57121f5868fbea9017";
        var entropyBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(entropyBytesHex));
        var entropy = (RandomGenerator) entropyBytes::readLongLE;

        assertEquals(576, entropyBytes.readableBytes());
        var a = BLS12381.randomToField(entropy);
        assertEquals(480, entropyBytes.readableBytes());
        var b = BLS12381.randomToField(entropy);
        assertEquals(384, entropyBytes.readableBytes());
        var c = BLS12381.randomToField(entropy);
        assertEquals(192, entropyBytes.readableBytes());
        var d = BLS12381.randomToField(entropy);
        assertEquals(96, entropyBytes.readableBytes());
        var e = BLS12381.randomToField(entropy);
        assertEquals(0, entropyBytes.readableBytes());

        entropyBytes.clear();
        BLS12381.fieldToBytes(a, entropyBytes);
        BLS12381.fieldToBytes(b, entropyBytes);
        BLS12381.fieldToBytes(c, entropyBytes);
        BLS12381.fieldToBytes(d, entropyBytes);
        BLS12381.fieldToBytes(e, entropyBytes);

        var expected = new byte[32];
        entropyBytes.readBytes(expected);
        assertEquals("1748522d0e0ab5dd6319edee1b60fd241ad60dd16124d262305f960960f2e0a8", ByteBufUtil.hexDump(expected));
        entropyBytes.readBytes(expected);
        assertEquals("30f83848c1fb540ba98ea32593bba4ec3a4c3a1e21dae696e21e28b78b36a1d7", ByteBufUtil.hexDump(expected));
        entropyBytes.readBytes(expected);
        assertEquals("233a56cb736a9eda91e6d1829d76a75f570f622ea42f2e9728113e1c969893e3", ByteBufUtil.hexDump(expected));
        entropyBytes.readBytes(expected);
        assertEquals("0ea04afc25b7e873c7309c2f9f5f929760eea9b3edb5fc3d9207fa0187a04465", ByteBufUtil.hexDump(expected));
        entropyBytes.readBytes(expected);
        assertEquals("5134505addbcc49cb6cf9881a6fa1f2eb17a9f75162e1da13a154397821a4a86", ByteBufUtil.hexDump(expected));
    }

    @Test
    void fieldMultiplyAdd_matches_fma_testVectors() {
        var out = Unpooled.buffer();
        for (var vector : FMA_VECTORS) {
            var a = BLS12381.bytesToField(vector.a.slice());
            var b = BLS12381.bytesToField(vector.b.slice());
            var c = BLS12381.bytesToField(vector.c.slice());
            var result = BLS12381.fieldMultiplyAdd(a, b, c);
            BLS12381.fieldToBytes(result, out.clear());
            assertEquals(vector.expectedHex, ByteBufUtil.hexDump(out));
        }
    }

    @Test
    void stringToBytes_and_bytesToString_roundTrip_for_short_strings() {
        var buf = Unpooled.buffer();

        BLS12381.stringToBytes(false, "hello", buf);
        assertEquals(5, buf.getUnsignedByte(0));
        var hello = buf.slice();
        assertEquals("hello", BLS12381.bytesToString(false, hello));
        assertEquals(0, hello.readableBytes());

        buf.clear();
        BLS12381.stringToBytes(false, "e\u0301", buf);
        assertEquals("e\u0301", BLS12381.bytesToString(false, buf.slice()));
    }

    @Test
    void stringToBytes_writes_expected_length_prefixes_at_boundaries_and_roundTrips() {
        var buf = Unpooled.buffer();

        var s128 = "a".repeat(0x80);
        BLS12381.stringToBytes(false, s128, buf);
        assertEquals(0x80, buf.getUnsignedByte(0));
        assertEquals(0x01, buf.getUnsignedByte(1));
        assertEquals(s128, BLS12381.bytesToString(false, buf.slice()));

        buf.clear();
        var s16383 = "a".repeat(0x3FFF);
        BLS12381.stringToBytes(false, s16383, buf);
        assertEquals(0xFF, buf.getUnsignedByte(0));
        assertEquals(0x7F, buf.getUnsignedByte(1));
        assertEquals(s16383, BLS12381.bytesToString(false, buf.slice()));

        buf.clear();
        var s16384 = "a".repeat(0x4000);
        assertThrows(IllegalArgumentException.class, () -> BLS12381.stringToBytes(false, s16384, buf));

        buf.clear();
        BLS12381.stringToBytes(true, s16384, buf);
        assertEquals(0x80, buf.getUnsignedByte(0));
        assertEquals(0x80, buf.getUnsignedByte(1));
        assertEquals(0x01, buf.getUnsignedByte(2));
        assertEquals(s16384, BLS12381.bytesToString(true, buf.slice()));

        buf.clear();
        var s16385 = "a".repeat(0x4001);
        assertThrows(IllegalArgumentException.class, () -> BLS12381.stringToBytes(false, s16385, buf));
        buf.clear();
        BLS12381.stringToBytes(true, s16385, buf);
        assertEquals(0x81, buf.getUnsignedByte(0));
        assertEquals(0x80, buf.getUnsignedByte(1));
        assertEquals(0x01, buf.getUnsignedByte(2));
        assertEquals(s16385, BLS12381.bytesToString(true, buf.slice()));

        buf.clear();
        var s65536 = "a".repeat(0x10000);
        assertThrows(IllegalArgumentException.class, () -> BLS12381.stringToBytes(false, s65536, buf));
        buf.clear();
        BLS12381.stringToBytes(true, s65536, buf);
        assertEquals(0x80, buf.getUnsignedByte(0));
        assertEquals(0x80, buf.getUnsignedByte(1));
        assertEquals(0x04, buf.getUnsignedByte(2));
        assertEquals(s65536, BLS12381.bytesToString(true, buf.slice()));

        buf.clear();
        var sTooLong = "a".repeat(0x200000);
        assertThrows(IllegalArgumentException.class, () -> BLS12381.stringToBytes(false, sTooLong, buf));
        buf.clear();
        assertThrows(IllegalArgumentException.class, () -> BLS12381.stringToBytes(true, sTooLong, buf));
    }

    @Test
    void bytesToString_rejects_nonCanonical_or_tooLong_length_encodings() {
        var buf = Unpooled.buffer();
        buf.writeByte(0x80).writeByte(0x00);
        assertThrows(IllegalArgumentException.class, () -> BLS12381.bytesToString(false, buf.slice()));

        buf.clear();
        buf.writeByte(0x80).writeByte(0x80).writeByte(0x00);
        assertThrows(IllegalArgumentException.class, () -> BLS12381.bytesToString(true, buf.slice()));

        buf.clear();
        buf.writeByte(0x80).writeByte(0x80);
        assertThrows(IllegalArgumentException.class, () -> BLS12381.bytesToString(false, buf.slice()));

        buf.clear();
        buf.writeByte(0xFF).writeByte(0xFF).writeByte(0x80);
        assertThrows(IllegalArgumentException.class, () -> BLS12381.bytesToString(true, buf.slice()));
    }

    private record G1Vector(ByteBuf privateKey, ByteBuf message, String expectedSignatureHex) {
        private static G1Vector parse(String line) {
            var parts = line.split(":", -1);
            if (parts.length != 3) {
                throw new IllegalArgumentException("Unexpected vector format: " + line);
            }
            var privateKey = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(parts[0])).asReadOnly();
            var message = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(parts[1])).asReadOnly();
            return new G1Vector(privateKey, message, parts[2]);
        }
    }

    private record ScalarVector(ByteBuf okmAscii, String expectedScalarHex) {
        private static ScalarVector parse(String line) {
            var parts = line.split(":", -1);
            if (parts.length != 2) {
                throw new IllegalArgumentException("Unexpected vector format: " + line);
            }
            var okmAscii = Unpooled.wrappedBuffer(parts[0].getBytes(StandardCharsets.US_ASCII)).asReadOnly();
            return new ScalarVector(okmAscii, parts[1]);
        }
    }

    private record FMAVector(ByteBuf a, ByteBuf b, ByteBuf c, String expectedHex) {
        private static FMAVector parse(String line) {
            var parts = line.split(":", -1);
            if (parts.length != 4) {
                throw new IllegalArgumentException("Unexpected vector format: " + line);
            }
            var a = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(parts[0])).asReadOnly();
            var b = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(parts[1])).asReadOnly();
            var c = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(parts[2])).asReadOnly();
            return new FMAVector(a, b, c, parts[3]);
        }
    }
}
