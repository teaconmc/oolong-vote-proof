package org.teacon.ovp.payload;

import io.netty.buffer.Unpooled;
import org.teacon.ovp.miracl.core.BLS12381.BIG;
import org.teacon.ovp.util.BLS12381;

import java.util.random.RandomGenerator;

public final class VoteChallenges {
    static final RandomGenerator RANDOM = RandomGenerator.of("SecureRandom");

    public static boolean validate(VoteClientContext context, ServerPRFAbsent evaluate) {
        var m = context.passwordHash.mul(context.randomScalar);
        var pair = BLS12381.pairingWithGeneratorNegative(m, context.serverKey.v, evaluate.n);
        return pair.isunity();
    }

    public static boolean validate(VoteClientContext context, IdentitySignature signature) {
        if (context.secretKeyOrZero.nbits() > 0) {
            var point = context.serverKey.w.mul(signature.rolesHash);
            point.add(context.serverKey.x);
            point.add(context.serverKey.y.mul(context.secretKeyOrZero));
            var pair = BLS12381.pairingWithGeneratorNegative(signature.a, point, signature.b);
            return pair.isunity();
        }
        return false;
    }

    public static boolean validate(ServerPublicKey serverKey, IdentityBlindProof proof) {
        var buf = Unpooled.buffer(1040);
        buf.writeLong(proof.work.getMostSignificantBits()).writeLong(proof.work.getLeastSignificantBits());
        var qPoint = BLS12381.hashToPoint(buf, 128 / Byte.SIZE).mul(proof.z);
        qPoint.sub(proof.id.id.mul(proof.c));
        var rPoint = serverKey.w.mul(proof.c).mul(proof.signature.rolesHash);
        rPoint.add(serverKey.x.mul(proof.c));
        rPoint.add(serverKey.y.mul(proof.z));
        var rPairing = BLS12381.pairingWithGeneratorNegative(proof.signature.a, rPoint, proof.signature.b.mul(proof.c));
        serverKey.dump(buf.clear());
        BLS12381.fieldToBytes(proof.d, buf);
        BLS12381.pointToSignature(qPoint, buf);
        BLS12381.pairingToIndexBE(rPairing, buf);
        var c = BLS12381.hashToScalar(buf, buf.readableBytes());
        return BIG.comp(proof.c, c) == 0;
    }

    private VoteChallenges() {
        throw new IllegalStateException("utility class");
    }
}
