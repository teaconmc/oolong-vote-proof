package org.teacon.ovp.payload;

import io.netty.buffer.Unpooled;
import org.teacon.ovp.miracl.core.BLS12381.BIG;
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.miracl.core.BLS12381.ECP2;
import org.teacon.ovp.util.BLS12381;

import java.util.random.RandomGenerator;

public final class VoteChallenges {
    static final RandomGenerator RANDOM = RandomGenerator.of("SecureRandom");

    public static boolean validate(VoteClientContext context, ServerPRFAbsent evaluate) {
        var m = context.passwordHash.mul(context.randomScalar.core());
        var pair = BLS12381.pairingWithGeneratorNegative(m, context.serverKey.v, evaluate.n);
        return pair.isunity();
    }

    public static boolean validate(VoteClientContext context, IdentitySignature signature) {
        var point = context.serverKey.w.mul(signature.rolesHash);
        point.add(context.serverKey.x);
        point.add(context.serverKey.y.mul(context.secretKey.core()));
        var pair = BLS12381.pairingWithGeneratorNegative(signature.a, point, signature.b);
        return pair.isunity();
    }

    public static boolean validate(VoteClientContext context, IdentityBlindProof proof) {
        var buf = Unpooled.buffer(1040);
        buf.writeLong(proof.work.getMostSignificantBits()).writeLong(proof.work.getLeastSignificantBits());
        var qPoint = BLS12381.hashToPoint(buf, 128 / Byte.SIZE).mul(proof.z);
        qPoint.sub(proof.id.id.mul(proof.c));
        var rPoint = context.serverKey.w.mul(proof.c).mul(proof.signature.rolesHash);
        rPoint.add(context.serverKey.x.mul(proof.c));
        rPoint.add(context.serverKey.y.mul(proof.z));
        var rPairing = BLS12381.pairingWithGeneratorNegative(proof.signature.a, rPoint, proof.signature.b.mul(proof.c));
        BLS12381.pointToPubKey(context.serverKey.w, buf.clear());
        BLS12381.pointToPubKey(context.serverKey.x, buf);
        BLS12381.pointToPubKey(context.serverKey.y, buf);
        BLS12381.fieldToBytes(proof.d, buf);
        BLS12381.pointToSignature(qPoint, buf);
        BLS12381.pairingToIndexBE(rPairing, buf);
        var c = BLS12381.hashToScalar(buf, buf.readableBytes());
        return BIG.comp(proof.c, c) == 0;
    }

    public static boolean validate(VoteServerContext context, IdentityBlindProof proof) {
        var buf = Unpooled.buffer(1040);
        buf.writeLong(proof.work.getMostSignificantBits()).writeLong(proof.work.getLeastSignificantBits());
        var w = ECP2.generator().mul(context.w);
        var x = ECP2.generator().mul(context.x);
        var y = ECP2.generator().mul(context.y);
        var qPoint = BLS12381.hashToPoint(buf, 128 / Byte.SIZE).mul(proof.z);
        qPoint.sub(proof.id.id.mul(proof.c));
        var rPoint = w.mul(proof.c).mul(proof.signature.rolesHash);
        rPoint.add(x.mul(proof.c));
        rPoint.add(y.mul(proof.z));
        var rPairing = BLS12381.pairingWithGeneratorNegative(proof.signature.a, rPoint, proof.signature.b.mul(proof.c));
        BLS12381.pointToPubKey(w, buf.clear());
        BLS12381.pointToPubKey(x, buf);
        BLS12381.pointToPubKey(y, buf);
        BLS12381.fieldToBytes(proof.d, buf);
        BLS12381.pointToSignature(qPoint, buf);
        BLS12381.pairingToIndexBE(rPairing, buf);
        var c = BLS12381.hashToScalar(buf, buf.readableBytes());
        return BIG.comp(proof.c, c) == 0;
    }

    public static boolean validate(ClientPointCommit commit, ClientRevocation revocation) {
        var pair = BLS12381.pairingWithGeneratorNegative(ECP.generator(), revocation.c, commit.s);
        return pair.isunity();
    }

    private VoteChallenges() {
        throw new IllegalStateException("utility class");
    }
}
