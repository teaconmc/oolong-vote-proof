package org.teacon.ovp.payload;

import io.netty.buffer.ByteBuf;
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.util.BLS12381;

import java.security.GeneralSecurityException;
import java.security.SignatureException;

public final class ClientPRFRequest {
    public static ClientPRFRequest load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new ClientPRFRequest(input);
        } catch (RuntimeException e) {
            throw new SignatureException("invalid client prf request", e);
        }
    }

    public void dump(ByteBuf output) {
        BLS12381.pointToSignature(this.m, output);
    }

    final ECP m;

    ClientPRFRequest(VoteClientContext ctx) {
        this.m = ctx.passwordHash.mul(ctx.randomScalar.core());
    }

    ClientPRFRequest(ByteBuf input) {
        this.m = BLS12381.signatureToPoint(input);
    }
}
