package org.teacon.ovp.payload;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.teacon.ovp.miracl.core.BLS12381.BIG;
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.util.BLS12381;
import org.teacon.ovp.util.ShortMnemonic;

import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Optional;
import java.util.random.RandomGenerator;

public final class ClientPRFSession {
    public static ClientPRFSession from(char[] pass) {
        return new ClientPRFSession(pass, VoteChallenges.RANDOM);
    }

    public static ClientPRFSession from(ClientPRFSession old, ServerPRFPresent answer) {
        try {
            return new ClientPRFSession(old, answer);
        } catch (RuntimeException e) {
            return old;
        }
    }

    public static ClientPRFSession from(ClientPRFSession old, ServerPRFPresent answer, ShortMnemonic recoveryKey) {
        try {
            return new ClientPRFSession(old, answer, recoveryKey);
        } catch (RuntimeException ex) {
            return old;
        }
    }

    public static ClientPRFSession load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new ClientPRFSession(input);
        } catch (RuntimeException e) {
            throw new InvalidKeyException("invalid client prf session", e);
        }
    }

    Optional<ClientSecretKey> secret() {
        return this.sMaster.nbits() == 0 ? Optional.empty() : Optional.of(new ClientSecretKey(this.sMaster));
    }

    public void dump(ByteBuf output) {
        BLS12381.fieldToSecretKey(this.r, output);
        BLS12381.pointToSignature(this.pPass, output);
        BLS12381.fieldToBytes(this.sMaster, output);
    }

    final BIG r;
    final ECP pPass;
    final BIG sMaster;

    ClientPRFSession(char[] pass, RandomGenerator rng) {
        var passBytes = Unpooled.copiedBuffer(CharBuffer.wrap(pass), StandardCharsets.UTF_8);
        this.r = BLS12381.randomToField(rng);
        this.pPass = BLS12381.hashToPoint(passBytes, passBytes.readableBytes());
        passBytes.setZero(0, passBytes.readableBytes());
        this.sMaster = new BIG(0);
    }

    ClientPRFSession(ClientPRFSession old, ServerPRFPresent answer) {
        this.r = old.r;
        this.pPass = old.pPass;
        var cipherKeyBytes = Unpooled.buffer(32);
        var prfResultBytes = Unpooled.buffer(48);
        BLS12381.pointToSignature(answer.n.mul(BLS12381.fieldInverse(old.r)), prfResultBytes);
        BLS12381.pbkdf2(prfResultBytes, 48, "password", false, cipherKeyBytes, 32);
        prfResultBytes.setZero(0, 48);
        var masterBytes = answer.ePass.decrypt(ByteBufUtil.getBytes(cipherKeyBytes));
        this.sMaster = BLS12381.secretKeyToField(Unpooled.wrappedBuffer(masterBytes));
    }

    ClientPRFSession(ClientPRFSession old, ServerPRFPresent answer, ShortMnemonic recoveryKey) {
        this.r = old.r;
        this.pPass = old.pPass;
        var cipherKeyBytes = Unpooled.buffer(32);
        var mnemBytes = Unpooled.copiedBuffer(CharBuffer.wrap(recoveryKey.chars()), StandardCharsets.UTF_8);
        BLS12381.pbkdf2(mnemBytes, mnemBytes.readableBytes(), "mnemonic", false, cipherKeyBytes, 32);
        mnemBytes.setZero(0, mnemBytes.readableBytes());
        var masterBytes = answer.ePass.decrypt(ByteBufUtil.getBytes(cipherKeyBytes));
        this.sMaster = BLS12381.secretKeyToField(Unpooled.wrappedBuffer(masterBytes));
    }

    ClientPRFSession(ByteBuf input) {
        this.r = BLS12381.secretKeyToField(input);
        this.pPass = BLS12381.signatureToPoint(input);
        this.sMaster = BLS12381.bytesToField(input);
    }
}
