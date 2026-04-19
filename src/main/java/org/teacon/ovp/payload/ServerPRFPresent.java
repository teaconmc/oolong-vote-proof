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

    public void dump(ByteBuf output) {
        BLS12381.pointToSignature(this.n, output);
        output.writeBytes(this.ePass, 0, 128).writeBytes(this.eMnem, 32, 96);
    }

    final ECP n;
    final byte[] ePass;
    final byte[] eMnem;

    ServerPRFPresent(ByteBuf input) {
        this.ePass = new byte[128];
        this.eMnem = new byte[128];
        this.n = BLS12381.signatureToPoint(input);
        var salt = input.readSlice(32);
        salt.readBytes(this.ePass, 0, 32).readerIndex(0).readBytes(this.eMnem, 0, 32);
        input.readBytes(this.ePass, 32, 96).readBytes(this.eMnem, 32, 96);
    }
}
