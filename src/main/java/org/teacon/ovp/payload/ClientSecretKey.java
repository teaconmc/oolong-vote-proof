package org.teacon.ovp.payload;

import io.netty.buffer.ByteBuf;
import org.teacon.ovp.miracl.core.BLS12381.BIG;
import org.teacon.ovp.util.BLS12381;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

public final class ClientSecretKey {
    public static ClientSecretKey load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new ClientSecretKey(input);
        } catch (RuntimeException e) {
            throw new InvalidKeyException("invalid client secret key", e);
        }
    }

    public void dump(ByteBuf output) {
        BLS12381.fieldToSecretKey(this.s, output);
    }

    final BIG s;

    ClientSecretKey(VoteClientContext ctx) {
        this.s = new BIG(ctx.secretKey.core());
    }

    ClientSecretKey(ByteBuf input) {
        this.s = BLS12381.secretKeyToField(input);
    }
}
