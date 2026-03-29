package org.teacon.ovp.payload;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.teacon.ovp.util.BLS12381;
import org.teacon.ovp.util.GCM256Cipher;
import org.teacon.ovp.util.ShortMnemonic;

import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.util.random.RandomGenerator;

public final class ClientPRFOverride {
    public static ClientPRFOverride from(ClientPRFSession session, ServerPRFAbsent answer,
                                         char[] pass, ShortMnemonic recoveryKey) {
        return new ClientPRFOverride(session, answer, pass, recoveryKey, VoteChallenges.RANDOM);
    }

    public static ClientPRFOverride load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new ClientPRFOverride(input);
        } catch (RuntimeException e) {
            throw new SignatureException("invalid client prf override request", e);
        }
    }

    public GCM256Cipher pass() {
        return this.ePass;
    }

    public GCM256Cipher mnem() {
        return this.eMnem;
    }

    public void dump(ByteBuf output) {
        output.writeBytes(this.ePass.raw()).writeBytes(this.eMnem.raw());
    }

    final GCM256Cipher ePass;
    final GCM256Cipher eMnem;

    ClientPRFOverride(ClientPRFSession session, ServerPRFAbsent answer,
                      char[] pass, ShortMnemonic recoveryKey, RandomGenerator rng) {
        var prfResult = answer.n.mul(BLS12381.fieldInverse(session.r));
        var masterBytes = Unpooled.buffer(32);
        BLS12381.fieldToSecretKey(BLS12381.randomToField(rng), masterBytes);
        var cipherKeyBytes = Unpooled.buffer(32);
        BLS12381.fieldToBytes(BLS12381.hashToScalar(pass, prfResult), cipherKeyBytes);
        this.ePass = new GCM256Cipher(rng, ByteBufUtil.getBytes(masterBytes), ByteBufUtil.getBytes(cipherKeyBytes));
        BLS12381.pbkdf2(recoveryKey.chars(), "mnemonic", cipherKeyBytes.clear(), 32);
        this.eMnem = new GCM256Cipher(rng, ByteBufUtil.getBytes(masterBytes), ByteBufUtil.getBytes(cipherKeyBytes));
    }

    ClientPRFOverride(ByteBuf input) {
        var bytes = new byte[60];
        input.readBytes(bytes);
        this.ePass = new GCM256Cipher(bytes);
        input.readBytes(bytes);
        this.eMnem = new GCM256Cipher(bytes);
    }
}
