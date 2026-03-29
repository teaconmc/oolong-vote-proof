package org.teacon.ovp.util;

import com.google.common.hash.Hashing;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.teacon.ovp.miracl.core.BLS12381.*;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.random.RandomGenerator;

public final class BLS12381 {
    private static final BIG MODULUS;
    private static final BIG CURVE_ORDER;
    private static final ECP2 GENERATOR_NEGATED;
    private static final int CURVE_ORDER_BYTES = 32;
    private static final int CURVE_ORDER_ZEROS = CONFIG_BIG.MODBYTES - CURVE_ORDER_BYTES;

    static {
        MODULUS = new BIG(ROM.Modulus);
        CURVE_ORDER = new BIG(ROM.CURVE_Order);
        GENERATOR_NEGATED = ECP2.generator();
        GENERATOR_NEGATED.neg();
    }

    public static String bytesToString(boolean enableLonger, ByteBuf input) {
        var length = input.readByte() & 0xFF;
        if (length >= 0x80) {
            length = (length & 0x7F) | (input.readByte() & 0xFF) << 7;
            if (length <= 0x7F) {
                throw new IllegalArgumentException("One byte length (" + length + ") with two bytes input");
            }
            if (length >= 0x4000) {
                if (!enableLonger) {
                    throw new IllegalArgumentException("String too long (max " + 0x3FFF + " bytes)");
                }
                length = (length & 0x3FFF) | (input.readByte() & 0xFF) << 14;
                if (length <= 0x3FFF) {
                    throw new IllegalArgumentException("Two bytes length (" + length + ") with three bytes input");
                }
                if (length >= 0x200000) {
                    throw new IllegalArgumentException("String too long (max " + 0x1FFFFF + " bytes)");
                }
            }
        }
        return input.readString(length, StandardCharsets.UTF_8);
    }

    public static void stringToBytes(boolean enableLonger, String input, ByteBuf output) {
        var length = ByteBufUtil.utf8Bytes(input);
        if (length < 0x80) {
            output.writeByte(length);
            output.writeCharSequence(input, StandardCharsets.UTF_8);
            return;
        }
        if (length < 0x4000) {
            output.writeByte(0x80 | length & 0x7F);
            output.writeByte(length >>> 7);
            output.writeCharSequence(input, StandardCharsets.UTF_8);
            return;
        }
        if (!enableLonger) {
            throw new IllegalArgumentException("String too long (max " + 0x3FFF + " bytes)");
        }
        if (length < 0x200000) {
            output.writeByte(0x80 | (length & 0x7F));
            output.writeByte(0x80 | ((length >>> 7) & 0x7F));
            output.writeByte(length >>> 14);
            output.writeCharSequence(input, StandardCharsets.UTF_8);
            return;
        }
        throw new IllegalArgumentException("String too long (max " + 0x1FFFFF + " bytes)");
    }

    public static BIG randomToField(RandomGenerator rng) {
        var field = new BIG(0);
        while (field.nbits() == 0) {
            var bytes = new byte[CONFIG_BIG.MODBYTES * 2];
            rng.nextBytes(bytes);
            var dbig = DBIG.fromBytes(bytes);
            field = dbig.mod(CURVE_ORDER);
        }
        return field;
    }

    public static BIG bytesToField(ByteBuf secretKey) {
        var bytes = new byte[CONFIG_BIG.MODBYTES];
        secretKey.readBytes(bytes, CURVE_ORDER_ZEROS, CURVE_ORDER_BYTES);
        var field = BIG.fromBytes(bytes);
        if (BIG.comp(field, CURVE_ORDER) >= 0) {
            throw new IllegalArgumentException("invalid field value");
        }
        return field;
    }

    public static void fieldToBytes(BIG field, ByteBuf secretKey) {
        if (BIG.comp(field, CURVE_ORDER) >= 0) {
            throw new IllegalArgumentException("invalid field value");
        }
        var bytes = new byte[CONFIG_BIG.MODBYTES];
        field.toBytes(bytes);
        secretKey.writeBytes(bytes, CURVE_ORDER_ZEROS, CURVE_ORDER_BYTES);
    }

    public static BIG secretKeyToField(ByteBuf secretKey) {
        var field = bytesToField(secretKey);
        if (field.nbits() == 0) {
            throw new IllegalArgumentException("invalid secret key");
        }
        return field;
    }

    public static void fieldToSecretKey(BIG field, ByteBuf secretKey) {
        if (field.nbits() == 0) {
            throw new IllegalArgumentException("invalid secret key");
        }
        fieldToBytes(field, secretKey);
    }

    public static BIG fieldMultiplyAdd(BIG a, BIG b, BIG c) {
        var result = BIG.modmul(a, b, CURVE_ORDER);
        result.add(c);
        result.norm();
        result.mod(CURVE_ORDER);
        return result;
    }

    public static BIG fieldInverse(BIG field) {
        var result = new BIG(field);
        result.invmodp(CURVE_ORDER);
        return result;
    }

    public static ByteBuf xmdExpand(ByteBuf message, int readLength, int outputMinLength, byte[] dst) {
        if (dst.length >= 256) {
            throw new IllegalArgumentException("xmd expand too long: " + dst.length + " >= 256");
        }
        // allocating
        var ell = (outputMinLength - 1) / 32 + 1;
        var okm = new byte[ell * 32];
        // hashing phase 1
        var h0 = new byte[32];
        var slices = message.readSlice(readLength).nioBuffers();
        // noinspection UnstableApiUsage
        var hasher = Hashing.sha256().newHasher();
        // noinspection UnstableApiUsage
        hasher.putBytes(h0).putBytes(h0);
        for (var slice : slices) {
            // noinspection UnstableApiUsage
            hasher.putBytes(slice);
        }
        // noinspection UnstableApiUsage
        hasher.putByte((byte) (outputMinLength / 256)).putByte((byte) (outputMinLength % 256)).putByte((byte) 0);
        // noinspection UnstableApiUsage
        hasher.putBytes(dst).putByte((byte) dst.length);
        // noinspection UnstableApiUsage
        hasher.hash().writeBytesTo(h0, 0, 32);
        // hashing phase 2
        var h1 = new byte[32];
        for (var i = 0; i < ell; ++i) {
            for (var j = 0; j < 32; ++j) {
                h1[j] ^= h0[j];
            }
            // noinspection UnstableApiUsage
            hasher = Hashing.sha256().newHasher();
            // noinspection UnstableApiUsage
            hasher.putBytes(h1).putByte((byte) (i + 1)).putBytes(dst).putByte((byte) dst.length);
            // noinspection UnstableApiUsage
            hasher.hash().writeBytesTo(h1, 0, 32);
            System.arraycopy(h1, 0, okm, i * 32, 32);
        }
        // result padded to n * 32 bytes
        return Unpooled.wrappedBuffer(okm, 0, outputMinLength);
    }

    public static BIG hashToScalar(ByteBuf message, int readLength) {
        var dst = "HashToScalar-".getBytes(StandardCharsets.US_ASCII);
        var okm = xmdExpand(message, readLength, 48, dst);
        var u = new FP(DBIG.fromBytes(ByteBufUtil.getBytes(okm, 0, 48)).mod(CURVE_ORDER));
        return u.redc();
    }

    public static BIG hashToScalar(char[] password, ECP point) {
        var normalizedPassword = Normalizer.normalize(CharBuffer.wrap(password), Normalizer.Form.NFKD);
        var messageCount = ByteBufUtil.utf8Bytes(normalizedPassword) + CONFIG_BIG.MODBYTES;
        var message = Unpooled.buffer(messageCount);
        message.writeCharSequence(normalizedPassword, StandardCharsets.UTF_8);
        BLS12381.pointToSignature(point, message);
        var result = hashToScalar(message, messageCount);
        message.setZero(0, messageCount);
        return result;
    }

    public static ECP hashToPoint(ByteBuf message, int readLength) {
        var dst = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_".getBytes(StandardCharsets.US_ASCII);
        var okm = xmdExpand(message, readLength, 2 * 64, dst);
        var u0 = new FP(DBIG.fromBytes(ByteBufUtil.getBytes(okm, 0, 64)).mod(MODULUS));
        var u1 = new FP(DBIG.fromBytes(ByteBufUtil.getBytes(okm, 64, 64)).mod(MODULUS));
        var p = ECP.map2point(u0);
        p.add(ECP.map2point(u1));
        p.cfp();
        p.affine();
        return p;
    }

    public static FP12 pairing(ECP signature, ECP2 pubKey) {
        return PAIR.fexp(PAIR.ate(pubKey, signature));
    }

    public static FP12 pairingWithGeneratorNegative(ECP signature1, ECP2 pubKey1, ECP signature2) {
        return PAIR.fexp(PAIR.ate2(pubKey1, signature1, GENERATOR_NEGATED, signature2));
    }

    public static void pairingToIndexBE(FP12 pairing, ByteBuf index) {
        var bytes = new byte[CONFIG_BIG.MODBYTES * 2];
        // MIRACL serializes FP12 using an internal tower layout/order (FP12 -> FP4 -> FP2)
        // here we normalize to common big-endian order by permuting the 6 FP2 numbers
        pairing.getc().getb().toBytes(bytes);
        index.writeBytes(bytes);
        pairing.geta().getb().toBytes(bytes);
        index.writeBytes(bytes);
        pairing.getb().geta().toBytes(bytes);
        index.writeBytes(bytes);
        pairing.getb().getb().toBytes(bytes);
        index.writeBytes(bytes);
        pairing.getc().geta().toBytes(bytes);
        index.writeBytes(bytes);
        pairing.geta().geta().toBytes(bytes);
        index.writeBytes(bytes);
    }

    public static void pointToPubKey(ECP2 point, ByteBuf pubKey) {
        if (point.is_infinity()) {
            pubKey.writeByte(0xC0).writeZero(CONFIG_BIG.MODBYTES * 2 - 1);
            return;
        }
        var bytes = new byte[CONFIG_BIG.MODBYTES * 2];
        point = new ECP2(point);
        point.affine();
        var x = point.getx();
        x.reduce();
        x.toBytes(bytes);
        var y = point.gety();
        if (y.islarger() == 1) {
            bytes[0] |= (byte) 0x20;
        }
        bytes[0] |= (byte) 0x80;
        pubKey.writeBytes(bytes);
    }

    public static void pointToSignature(ECP point, ByteBuf signature) {
        if (point.is_infinity()) {
            signature.writeByte(0xC0).writeZero(CONFIG_BIG.MODBYTES - 1);
            return;
        }
        var bytes = new byte[CONFIG_BIG.MODBYTES];
        point = new ECP(point);
        point.affine();
        var x = point.getx();
        x.redc().toBytes(bytes);
        var y = point.gety();
        if (y.islarger() == 1) {
            bytes[0] |= (byte) 0x20;
        }
        bytes[0] |= (byte) 0x80;
        signature.writeBytes(bytes);
    }

    public static ECP2 pubKeyToPoint(ByteBuf pubKey) {
        var bytes = ByteBufUtil.getBytes(pubKey.readSlice(CONFIG_BIG.MODBYTES * 2));
        var head = bytes[0];
        var compressed = head & 0x80;
        if (compressed != 0x80) {
            throw new IllegalArgumentException("invalid pubkey");
        }
        var infinity = head & 0x40;
        if (infinity == 0x40) {
            var blank = head & 0x3F;
            for (var i = 1; i < CONFIG_BIG.MODBYTES * 2; ++i) {
                blank |= bytes[i] & 0xFF;
            }
            if (blank != 0) {
                throw new IllegalArgumentException("invalid pubkey");
            }
            return new ECP2();
        }
        var sign = head & 0x20;
        bytes[0] &= 0x1F;
        var x = FP2.fromBytes(bytes);
        bytes[0] = head;
        var point = new ECP2(x, 0);
        if ((point.gety().islarger() == 1) != (sign == 0x20)) {
            point.neg();
        }
        return point;
    }

    public static ECP signatureToPoint(ByteBuf signature) {
        var bytes = ByteBufUtil.getBytes(signature.readSlice(CONFIG_BIG.MODBYTES));
        var head = bytes[0];
        var compressed = head & 0x80;
        if (compressed != 0x80) {
            throw new IllegalArgumentException("invalid signature");
        }
        var infinity = head & 0x40;
        if (infinity == 0x40) {
            var blank = head & 0x3F;
            for (var i = 1; i < CONFIG_BIG.MODBYTES; ++i) {
                blank |= bytes[i] & 0xFF;
            }
            if (blank != 0) {
                throw new IllegalArgumentException("invalid signature");
            }
            return new ECP();
        }
        var sign = head & 0x20;
        bytes[0] &= 0x1F;
        var x = BIG.fromBytes(bytes);
        bytes[0] = head;
        var point = new ECP(x, 0);
        if ((point.gety().islarger() == 1) != (sign == 0x20)) {
            point.neg();
        }
        return point;
    }

    public static ECP2 pubKeySubgroupCheck(ECP2 pubKey) {
        if (!pubKey.mul(CURVE_ORDER).is_infinity()) {
            throw new IllegalArgumentException("invalid pubkey");
        }
        return pubKey;
    }

    public static ECP signatureSubgroupCheck(ECP signature) {
        if (!signature.mul(CURVE_ORDER).is_infinity()) {
            throw new IllegalArgumentException("invalid signature");
        }
        return signature;
    }

    public static void skToPk(BIG secretKey, ByteBuf pubKey) {
        var point = ECP2.generator();
        point = point.mul(secretKey);
        pointToPubKey(point, pubKey);
    }

    public static ECP2 keyValidate(ByteBuf pubKey) {
        var point = pubKeyToPoint(pubKey);
        if (point.is_infinity()) {
            throw new IllegalArgumentException("invalid pubkey");
        }
        return pubKeySubgroupCheck(point);
    }

    public static void coreSign(BIG secretKey, ByteBuf message, int readLength, ByteBuf signature) {
        var point = hashToPoint(message, readLength);
        point = point.mul(secretKey);
        pointToSignature(point, signature);
    }

    public static boolean coreVerify(ByteBuf pubKey, ByteBuf message, int readLength, ByteBuf signature) {
        try {
            var signPoint = signatureSubgroupCheck(signatureToPoint(signature));
            var keyPoint = keyValidate(pubKey);
            var pair = pairingWithGeneratorNegative(hashToPoint(message, readLength), keyPoint, signPoint);
            return pair.isunity();
        } catch (RuntimeException e) {
            return false;
        }
    }

    public static void pbkdf2(char[] password, String salt, ByteBuf output, int outputLength) {
        if (outputLength < 0) {
            throw new IllegalArgumentException("outputLength < 0");
        }
        if (outputLength == 0) {
            return;
        }
        var normalizedPassword = Normalizer.normalize(CharBuffer.wrap(password), Normalizer.Form.NFKD).toCharArray();
        var saltBytes = Normalizer.normalize(salt, Normalizer.Form.NFKD).getBytes(StandardCharsets.UTF_8);
        var spec = new PBEKeySpec(normalizedPassword, saltBytes, 2048, outputLength * 8);
        try {
            var skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            var derived = skf.generateSecret(spec).getEncoded();
            if (derived.length != outputLength) {
                throw new IllegalStateException("unexpected PBKDF2 output length: " + derived.length + " != " + outputLength);
            }
            output.writeBytes(derived);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        } finally {
            spec.clearPassword();
            Arrays.fill(normalizedPassword, '\0');
        }
    }

    private BLS12381() {
        throw new IllegalStateException("utility class");
    }
}
