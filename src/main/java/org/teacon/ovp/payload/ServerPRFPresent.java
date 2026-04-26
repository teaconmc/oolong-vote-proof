package org.teacon.ovp.payload;

import io.netty.buffer.ByteBuf;
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.util.BLS12381;

import java.security.GeneralSecurityException;
import java.security.SignatureException;

public final class ServerPRFPresent {
    public static ServerPRFPresent load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new ServerPRFPresent(input);
        } catch (RuntimeException e) {
            throw new SignatureException("invalid server prf evaluation", e);
        }
    }

    public String envelope() {
        return this.envelope;
    }

    public void dump(ByteBuf output) {
        BLS12381.pointToSignature(this.n, output);
        BLS12381.decodeEnvelope(this.envelope, output);
    }

    final ECP n;
    final String envelope;

    ServerPRFPresent(ByteBuf input) {
        this.n = BLS12381.signatureToPoint(input);
        this.envelope = BLS12381.encodeEnvelope(input);
    }
}
