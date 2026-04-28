package org.teacon.ovp.payload;

import io.netty.buffer.ByteBuf;
import org.teacon.ovp.miracl.core.BLS12381.ECP2;
import org.teacon.ovp.util.BLS12381;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

public final class ServerPublicKey {
    public static ServerPublicKey load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new ServerPublicKey(input);
        } catch (RuntimeException e) {
            throw new InvalidKeyException("invalid server public key", e);
        }
    }

    public void dump(ByteBuf output) {
        BLS12381.pointToPubKey(this.v, output);
        BLS12381.pointToPubKey(this.w, output);
        BLS12381.pointToPubKey(this.x, output);
        BLS12381.pointToPubKey(this.y, output);
    }

    final ECP2 v;
    final ECP2 w;
    final ECP2 x;
    final ECP2 y;

    ServerPublicKey(ServerSecretKey sk) {
        var g = ECP2.generator();
        this.v = g.mul(sk.v);
        this.w = g.mul(sk.w);
        this.x = g.mul(sk.x);
        this.y = g.mul(sk.y);
    }

    ServerPublicKey(ByteBuf input) {
        this.v = BLS12381.keyValidate(input);
        this.w = BLS12381.keyValidate(input);
        this.x = BLS12381.keyValidate(input);
        this.y = BLS12381.keyValidate(input);
    }
}
