package org.teacon.ovp.payload;

import org.teacon.ovp.util.BLS12381;

import java.util.random.RandomGenerator;

public final class VoteChallenges {
    static final RandomGenerator RANDOM = RandomGenerator.of("SecureRandom");

    public static boolean validate(ServerPublicKey serverKey, ClientPRFRequest request, ServerPRFAbsent evaluate) {
        var pair = BLS12381.pairingWithGeneratorNegative(request.m, serverKey.v, evaluate.n);
        return pair.isunity();
    }

    private VoteChallenges() {
        throw new IllegalStateException("utility class");
    }
}
