package org.teacon.ovp.payload;

import io.netty.buffer.ByteBuf;
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.util.BLS12381;

import java.security.GeneralSecurityException;
import java.security.SignatureException;

public final class ClientPRFOverride {
    public static ClientPRFOverride load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new ClientPRFOverride(input);
        } catch (RuntimeException e) {
            throw new SignatureException("invalid client prf override request", e);
        }
    }

    public String envelope() {
        return this.envelope;
    }

    public void dump(ByteBuf output) {
        BLS12381.pointToSignature(this.s, output);
        BLS12381.decodeEnvelope(this.envelope, output);
    }

    final ECP s;
    final String envelope;

    ClientPRFOverride(VoteClientContext context, String envelope) {
        this.s = ECP.generator().mul(context.secretKey.core());
        this.envelope = envelope;
    }

    ClientPRFOverride(ByteBuf input) {
        this.s = BLS12381.signatureToPoint(input);
        this.envelope = BLS12381.encodeEnvelope(input);
    }
}
