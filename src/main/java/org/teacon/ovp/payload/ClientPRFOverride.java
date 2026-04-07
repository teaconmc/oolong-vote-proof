package org.teacon.ovp.payload;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.teacon.ovp.util.BLS12381;
import org.teacon.ovp.util.GCM256Cipher;
import org.teacon.ovp.util.ShortMnemonic;

import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.util.random.RandomGenerator;

public final class ClientPRFOverride {
    public static ClientPRFOverride from(ClientPRFSession session, ServerPRFAbsent answer, ShortMnemonic recoveryKey) {
        return new ClientPRFOverride(session, answer, recoveryKey, VoteChallenges.RANDOM);
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

    ClientPRFOverride(ClientPRFSession session, ServerPRFAbsent answer, ShortMnemonic recovery, RandomGenerator rng) {
        var masterBytes = Unpooled.buffer(32);
        BLS12381.fieldToSecretKey(BLS12381.randomToField(rng), masterBytes);
        var cipherKeyBytes = Unpooled.buffer(32);
        var prfResultBytes = Unpooled.buffer(48);
        BLS12381.pointToSignature(answer.n.mul(BLS12381.fieldInverse(session.r)), prfResultBytes);
        BLS12381.pbkdf2(prfResultBytes, 48, "password", false, cipherKeyBytes, 32);
        prfResultBytes.setZero(0, 48);
        this.ePass = new GCM256Cipher(rng, ByteBufUtil.getBytes(masterBytes), ByteBufUtil.getBytes(cipherKeyBytes));
        var mnemBytes = Unpooled.copiedBuffer(CharBuffer.wrap(recovery.chars()), StandardCharsets.UTF_8);
        BLS12381.pbkdf2(mnemBytes, mnemBytes.readableBytes(), "mnemonic", false, cipherKeyBytes.clear(), 32);
        mnemBytes.setZero(0, mnemBytes.readableBytes());
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
