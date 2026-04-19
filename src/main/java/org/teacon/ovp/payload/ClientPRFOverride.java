package org.teacon.ovp.payload;

import io.netty.buffer.ByteBuf;
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.util.BLS12381;

import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.util.Arrays;

public final class ClientPRFOverride {
    public static ClientPRFOverride load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new ClientPRFOverride(input);
        } catch (RuntimeException e) {
            throw new SignatureException("invalid client prf override request", e);
        }
    }

    public void dump(ByteBuf output) {
        BLS12381.pointToSignature(this.s, output);
        output.writeBytes(this.ePassMnem, 0, 224);
    }

    final ECP s;
    final byte[] ePassMnem;

    ClientPRFOverride(ClientSecretKey secret, byte[] envelopePayload) {
        this.s = ECP.generator().mul(secret.s);
        this.ePassMnem = Arrays.copyOf(envelopePayload, 224);
    }

    ClientPRFOverride(ByteBuf input) {
        this.s = BLS12381.signatureToPoint(input);
        this.ePassMnem = new byte[224];
        input.readBytes(this.ePassMnem);
    }
}
