package org.teacon.ovp.payload;

import io.netty.buffer.ByteBuf;
import org.teacon.ovp.miracl.core.BLS12381.ECP2;
import org.teacon.ovp.util.BLS12381;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

public final class ClientRevocation {
    public static ClientRevocation from(ClientSecretKey secretKey) {
        return new ClientRevocation(secretKey);
    }

    public static ClientRevocation load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new ClientRevocation(input);
        } catch (RuntimeException e) {
            throw new InvalidKeyException("invalid revocation key", e);
        }
    }

    public void dump(ByteBuf buf) {
        BLS12381.pointToPubKey(this.c, buf);
    }

    final ECP2 c;

    ClientRevocation(ClientSecretKey secretKey) {
        this.c = ECP2.generator().mul(secretKey.s);
    }

    ClientRevocation(ByteBuf input) {
        this.c = BLS12381.pubKeyToPoint(input);
    }
}
