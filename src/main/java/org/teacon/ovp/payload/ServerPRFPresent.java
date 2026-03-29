package org.teacon.ovp.payload;

import io.netty.buffer.ByteBuf;
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.util.BLS12381;
import org.teacon.ovp.util.GCM256Cipher;

import java.security.GeneralSecurityException;
import java.security.SignatureException;

public final class ServerPRFPresent {
    public static ServerPRFPresent from(ServerSecretKey serverKey, ClientPRFRequest request,
                                        GCM256Cipher passEnvelope, GCM256Cipher mnemEnvelope) {
        return new ServerPRFPresent(serverKey, request, passEnvelope, mnemEnvelope);
    }

    public static ServerPRFPresent load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new ServerPRFPresent(input);
        } catch (RuntimeException e) {
            throw new SignatureException("invalid server prf evaluation", e);
        }
    }

    public void dump(ByteBuf output) {
        BLS12381.pointToSignature(this.n, output);
        output.writeBytes(this.ePass.raw()).writeBytes(this.eMnem.raw());
    }

    final ECP n;
    final GCM256Cipher ePass;
    final GCM256Cipher eMnem;

    ServerPRFPresent(ServerSecretKey serverSecret, ClientPRFRequest request, GCM256Cipher ePass, GCM256Cipher eMnem) {
        this.n = request.m.mul(serverSecret.v);
        this.ePass = ePass;
        this.eMnem = eMnem;
    }

    ServerPRFPresent(ByteBuf input) {
        var bytes = new byte[60];
        this.n = BLS12381.signatureToPoint(input);
        input.readBytes(bytes);
        this.ePass = new GCM256Cipher(bytes);
        input.readBytes(bytes);
        this.eMnem = new GCM256Cipher(bytes);
    }
}
