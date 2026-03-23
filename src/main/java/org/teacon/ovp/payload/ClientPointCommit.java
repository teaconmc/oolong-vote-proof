package org.teacon.ovp.payload;

import io.netty.buffer.ByteBuf;
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.util.BLS12381;

import java.security.GeneralSecurityException;
import java.security.SignatureException;

public final class ClientPointCommit {
    public static ClientPointCommit from(ClientSecretKey secretKey) {
        return new ClientPointCommit(secretKey);
    }

    public static ClientPointCommit load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new ClientPointCommit(input);
        } catch (RuntimeException e) {
            throw new SignatureException("invalid masked client key", e);
        }
    }

    public void dump(ByteBuf output) {
        BLS12381.pointToSignature(this.s, output);
    }

    final ECP s;

    ClientPointCommit(ClientSecretKey secretKey) {
        this.s = ECP.generator().mul(secretKey.s);
    }

    ClientPointCommit(ByteBuf input) {
        this.s = BLS12381.signatureToPoint(input);
    }
}
