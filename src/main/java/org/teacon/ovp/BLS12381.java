package org.teacon.ovp;

import org.teacon.ovp.miracl.core.BLS12381.*;
import org.teacon.ovp.miracl.core.HMAC;

import java.nio.charset.StandardCharsets;

public final class BLS12381 {
    private static final BIG ZERO;
    private static final BIG CURVE_ORDER;
    private static final ECP2 GENERATOR_NEGATED;
    private static final int CURVE_ORDER_BYTES = 32;
    private static final int CURVE_ORDER_ZEROS = CONFIG_BIG.MODBYTES - CURVE_ORDER_BYTES;

    static {
        ZERO = new BIG(0);
        CURVE_ORDER = new BIG(ROM.CURVE_Order);
        GENERATOR_NEGATED = ECP2.generator();
        GENERATOR_NEGATED.neg();
    }

    public static BIG secretKeyToField(byte[] secretKey) {
        if (secretKey.length != CURVE_ORDER_BYTES) {
            throw new IllegalArgumentException("invalid secret key");
        }
        var bytes = new byte[CONFIG_BIG.MODBYTES];
        System.arraycopy(secretKey, 0, bytes, CURVE_ORDER_ZEROS, CURVE_ORDER_BYTES);
        var field = BIG.fromBytes(bytes);
        if (BIG.comp(field, ZERO) <= 0 || BIG.comp(field, CURVE_ORDER) >= 0) {
            throw new IllegalArgumentException("invalid secret key");
        }
        return field;
    }

    public static ECP hashToPoint(byte[] message) {
        var dst = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_".getBytes(StandardCharsets.US_ASCII);
        var u = BLS.hash_to_field(HMAC.MC_SHA2, CONFIG_CURVE.HASH_TYPE, dst, message, 2);
        var p = ECP.map2point(u[0]);
        p.add(ECP.map2point(u[1]));
        p.cfp();
        p.affine();
        return p;
    }

    public static FP12 pairing(ECP signature, ECP2 pubKey) {
        return PAIR.fexp(PAIR.ate(pubKey, signature));
    }

    public static FP12 pairing(ECP signature1, ECP2 pubKey1, ECP signature2, ECP2 pubKey2) {
        return PAIR.fexp(PAIR.ate2(pubKey1, signature1, pubKey2, signature2));
    }

    public static byte[] pointToPubKey(ECP2 pubKey) {
        var bytes = new byte[CONFIG_BIG.MODBYTES * 2];
        if (pubKey.is_infinity()) {
            bytes[0] |= (byte) 0xC0;
            return bytes;
        }
        pubKey = new ECP2(pubKey);
        pubKey.affine();
        var x = pubKey.getx();
        x.reduce();
        x.toBytes(bytes);
        var y = pubKey.gety();
        if (y.islarger() == 1) {
            bytes[0] |= (byte) 0x20;
        }
        bytes[0] |= (byte) 0x80;
        return bytes;
    }

    public static byte[] pointToSignature(ECP point) {
        var bytes = new byte[CONFIG_BIG.MODBYTES];
        if (point.is_infinity()) {
            bytes[0] |= (byte) 0xC0;
            return bytes;
        }
        point = new ECP(point);
        point.affine();
        var x = point.getx();
        x.redc().toBytes(bytes);
        var y = point.gety();
        if (y.islarger() == 1) {
            bytes[0] |= (byte) 0x20;
        }
        bytes[0] |= (byte) 0x80;
        return bytes;
    }

    public static ECP2 pubKeyToPoint(byte[] pubKey) {
        if (pubKey.length != CONFIG_BIG.MODBYTES * 2) {
            throw new IllegalArgumentException("invalid pubkey");
        }
        var head = pubKey[0];
        var compressed = head & 0x80;
        if (compressed != 0x80) {
            throw new IllegalArgumentException("invalid pubkey");
        }
        var infinity = head & 0x40;
        if (infinity == 0x40) {
            var blank = head & 0x3F;
            for (var i = 1; i < CONFIG_BIG.MODBYTES * 2; ++i) {
                blank |= pubKey[i] & 0xFF;
            }
            if (blank != 0) {
                throw new IllegalArgumentException("invalid pubkey");
            }
            return new ECP2();
        }
        var sign = head & 0x20;
        pubKey[0] &= 0x1F;
        var x = FP2.fromBytes(pubKey);
        pubKey[0] = head;
        var point = new ECP2(x, 0);
        if ((point.gety().islarger() == 1) != (sign == 0x20)) {
            point.neg();
        }
        return point;
    }

    public static ECP signatureToPoint(byte[] signature) {
        if (signature.length != CONFIG_BIG.MODBYTES) {
            throw new IllegalArgumentException("invalid signature");
        }
        var head = signature[0];
        var compressed = head & 0x80;
        if (compressed != 0x80) {
            throw new IllegalArgumentException("invalid signature");
        }
        var infinity = head & 0x40;
        if (infinity == 0x40) {
            var blank = head & 0x3F;
            for (var i = 1; i < CONFIG_BIG.MODBYTES; ++i) {
                blank |= signature[i] & 0xFF;
            }
            if (blank != 0) {
                throw new IllegalArgumentException("invalid signature");
            }
            return new ECP();
        }
        var sign = head & 0x20;
        signature[0] &= 0x1F;
        var x = BIG.fromBytes(signature);
        signature[0] = head;
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

    public static byte[] skToPk(BIG secretKey) {
        var point = ECP2.generator();
        point = point.mul(secretKey);
        return pointToPubKey(point);
    }

    public static ECP2 keyValidate(byte[] pubKey) {
        var point = pubKeyToPoint(pubKey);
        if (ECP2.generator().equals(point)) {
            throw new IllegalArgumentException("invalid pubkey");
        }
        return pubKeySubgroupCheck(point);
    }

    public static byte[] coreSign(BIG secretKey, byte[] input) {
        var point = hashToPoint(input);
        point = point.mul(secretKey);
        return pointToSignature(point);
    }

    public static boolean coreVerify(byte[] pubKey, byte[] message, byte[] signature) {
        try {
            var signPoint = signatureSubgroupCheck(signatureToPoint(signature));
            var keyPoint = keyValidate(pubKey);
            var pair = pairing(hashToPoint(message), keyPoint, signPoint, GENERATOR_NEGATED);
            return pair.isunity();
        } catch (RuntimeException e) {
            return false;
        }
    }

    private BLS12381() {
        throw new IllegalStateException("utility class");
    }
}
