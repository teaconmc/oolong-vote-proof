package org.teacon.ovp.payload;

import com.google.common.hash.HashCode;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.teacon.ovp.miracl.core.BLS12381.CONFIG_BIG;
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.miracl.core.BLS12381.ECP2;
import org.teacon.ovp.util.BLS12381;

import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.util.UUID;

public final class IdentityDerivation {
    public static IdentityDerivation from(UUID work, ClientSecretKey secretKey) {
        return new IdentityDerivation(work, secretKey);
    }

    public static IdentityDerivation load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new IdentityDerivation(input);
        } catch (RuntimeException e) {
            throw new SignatureException("invalid server signature", e);
        }
    }

    public HashCode index() {
        var buf = Unpooled.buffer(CONFIG_BIG.MODBYTES * 12);
        BLS12381.pairingToIndexBE(BLS12381.pairing(this.id, ECP2.generator()), buf);
        return HashCode.fromBytes(ByteBufUtil.getBytes(buf, 0, buf.readableBytes()));
    }

    public void dump(ByteBuf output) {
        BLS12381.pointToSignature(this.id, output);
    }

    final ECP id;

    IdentityDerivation(UUID work, ClientSecretKey secretKey) {
        var workLength = 128 / Byte.SIZE;
        var buf = Unpooled.buffer(workLength);
        buf.writeLong(work.getMostSignificantBits()).writeLong(work.getLeastSignificantBits());
        this.id = BLS12381.hashToPoint(buf, workLength).mul(secretKey.s);
    }

    IdentityDerivation(ByteBuf input) {
        this.id = BLS12381.signatureToPoint(input);
    }
}
