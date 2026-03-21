package org.teacon.ovp;

import com.google.common.hash.Hashing;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.teacon.ovp.miracl.core.BLS12381.*;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public final class BLS12381 {
    private static final BIG ZERO;
    private static final BIG MODULUS;
    private static final BIG CURVE_ORDER;
    private static final ECP2 GENERATOR_NEGATED;
    private static final int CURVE_ORDER_BYTES = 32;
    private static final int CURVE_ORDER_ZEROS = CONFIG_BIG.MODBYTES - CURVE_ORDER_BYTES;

    static {
        ZERO = new BIG(0);
        MODULUS = new BIG(ROM.Modulus);
        CURVE_ORDER = new BIG(ROM.CURVE_Order);
        GENERATOR_NEGATED = ECP2.generator();
        GENERATOR_NEGATED.neg();
    }

    public static ByteBuf packToBytes(int sizeHint, Object... inputs) {
        var output = Unpooled.buffer(sizeHint);
        for (var i = 0; i < inputs.length; ++i) {
            var input = inputs[i];
            switch (input) {
                case ECP e -> pointToSignature(e, output);
                case FP12 f -> pairingToIndex(f, output);
                case String s -> {
                    var len = ByteBufUtil.utf8Bytes(s);
                    if (len < 0x80) {
                        output.writeByte(len);
                    } else if (len < 0x4000) {
                        output.writeByte(0x80 | (len & 0x7F));
                        output.writeByte(len >>> 7);
                    } else if (len < 0x200000) {
                        output.writeByte(0x80 | (len & 0x7F));
                        output.writeByte(0x80 | ((len >>> 7) & 0x7F));
                        output.writeByte(len >>> 14);
                    } else {
                        throw new IllegalArgumentException("inputs[" + i + "] too long: " + len + " bytes");
                    }
                    output.writeCharSequence(s, StandardCharsets.UTF_8);
                }
                default -> throw new IllegalArgumentException("inputs[" + i + "] invalid");
            }
        }
        return output.asReadOnly();
    }

    public static BIG randomToField(SecureRandom random) {
        var field = new BIG(0);
        while (BIG.comp(field, ZERO) <= 0) {
            var bytes = new byte[BIG.DNLEN * Long.BYTES];
            random.nextBytes(bytes);
            var dbig = DBIG.fromBytes(bytes);
            field = dbig.mod(CURVE_ORDER);
        }
        return field;
    }

    public static BIG secretKeyToField(ByteBuf secretKey) {
        var bytes = new byte[CONFIG_BIG.MODBYTES];
        secretKey.readBytes(bytes, CURVE_ORDER_ZEROS, CURVE_ORDER_BYTES);
        var field = BIG.fromBytes(bytes);
        if (BIG.comp(field, ZERO) <= 0 || BIG.comp(field, CURVE_ORDER) >= 0) {
            throw new IllegalArgumentException("invalid secret key");
        }
        return field;
    }

    public static void fieldToSecretKey(BIG field, ByteBuf secretKey) {
        if (BIG.comp(field, ZERO) <= 0 || BIG.comp(field, CURVE_ORDER) >= 0) {
            throw new IllegalArgumentException("invalid secret key");
        }
        var bytes = new byte[CONFIG_BIG.MODBYTES];
        field.toBytes(bytes);
        secretKey.writeBytes(bytes, CURVE_ORDER_ZEROS, CURVE_ORDER_BYTES);
    }

    private static byte[] paddedXmdExpand(ByteBuf message, int readLength, int outputMinLength, byte[] dst) {
        if (dst.length >= 256) {
            throw new IllegalArgumentException("xmd expand too long: " + dst.length + " >= 256");
        }
        // allocating
        var ell = (outputMinLength - 1) / 32 + 1;
        var okm = new byte[ell * 32];
        // hashing phase 1
        var h0 = new byte[32];
        // noinspection UnstableApiUsage
        var hasher = Hashing.sha256().newHasher();
        // noinspection UnstableApiUsage
        hasher.putBytes(new byte[64]).putBytes(message.readSlice(readLength).nioBuffer());
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
            hasher.hash().writeBytesTo(h1,0, 32);
            System.arraycopy(h1, 0, okm, i * 32, 32);
        }
        // result padded to n * 32 bytes
        return okm;
    }

    public static BIG hashToScalar(ByteBuf message, int readLength) {
        var dst = "HashToScalar-".getBytes(StandardCharsets.US_ASCII);
        var okm = paddedXmdExpand(message, readLength, 48, dst);
        var u = new FP(DBIG.fromBytes(Arrays.copyOf(okm, 48)).mod(CURVE_ORDER));
        return u.redc();
    }

    public static ECP hashToPoint(ByteBuf message, int readLength) {
        var dst = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_".getBytes(StandardCharsets.US_ASCII);
        var okm = paddedXmdExpand(message, readLength, 2 * 64, dst);
        var fd = new byte[64];
        System.arraycopy(okm, 0, fd, 0, 64);
        var p = ECP.map2point(new FP(DBIG.fromBytes(fd).mod(MODULUS)));
        System.arraycopy(okm, 64, fd, 0, 64);
        p.add(ECP.map2point(new FP(DBIG.fromBytes(fd).mod(MODULUS))));
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

    public static void pairingToIndex(FP12 pairing, ByteBuf index) {
        var bytes = new byte[CONFIG_BIG.MODBYTES * 12];
        pairing.toBytes(bytes);
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
        if (ECP2.generator().equals(point)) {
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

    private BLS12381() {
        throw new IllegalStateException("utility class");
    }
}
