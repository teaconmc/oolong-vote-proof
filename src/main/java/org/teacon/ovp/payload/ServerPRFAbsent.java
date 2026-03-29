package org.teacon.ovp.payload;

import io.netty.buffer.ByteBuf;
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.util.BLS12381;

import java.security.GeneralSecurityException;
import java.security.SignatureException;

public final class ServerPRFAbsent {
    public static ServerPRFAbsent from(ServerSecretKey serverSecret, ClientPRFRequest request) {
        return new ServerPRFAbsent(serverSecret, request);
    }

    public static ServerPRFAbsent load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new ServerPRFAbsent(input);
        } catch (RuntimeException e) {
            throw new SignatureException("invalid server prf evaluation", e);
        }
    }

    public void dump(ByteBuf output) {
        BLS12381.pointToSignature(this.n, output);
    }

    final ECP n;

    ServerPRFAbsent(ServerSecretKey serverSecret, ClientPRFRequest request) {
        this.n = request.m.mul(serverSecret.v);
    }

    ServerPRFAbsent(ServerPRFPresent answer) {
        this.n = answer.n;
    }

    ServerPRFAbsent(ByteBuf input) {
        this.n = BLS12381.signatureToPoint(input);
    }
}
