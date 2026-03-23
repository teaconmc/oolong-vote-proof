package org.teacon.ovp.payload;

import io.netty.buffer.ByteBuf;
import org.teacon.ovp.miracl.core.BLS12381.BIG;
import org.teacon.ovp.util.BLS12381;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

public final class ServerSecretKey {
    public static ServerSecretKey load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new ServerSecretKey(input);
        } catch (RuntimeException e) {
            throw new InvalidKeyException("invalid server secret key", e);
        }
    }

    public void dump(ByteBuf output) {
        BLS12381.fieldToSecretKey(this.v, output);
        BLS12381.fieldToSecretKey(this.w, output);
        BLS12381.fieldToSecretKey(this.x, output);
        BLS12381.fieldToSecretKey(this.y, output);
    }

    final BIG v;
    final BIG w;
    final BIG x;
    final BIG y;

    ServerSecretKey(ByteBuf input) throws GeneralSecurityException {
        this.v = BLS12381.secretKeyToField(input);
        this.w = BLS12381.secretKeyToField(input);
        this.x = BLS12381.secretKeyToField(input);
        this.y = BLS12381.secretKeyToField(input);
    }
}
