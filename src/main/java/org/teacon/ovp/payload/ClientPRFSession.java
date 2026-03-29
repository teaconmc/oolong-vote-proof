package org.teacon.ovp.payload;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.teacon.ovp.miracl.core.BLS12381.BIG;
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.util.BLS12381;
import org.teacon.ovp.util.ShortMnemonic;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Optional;
import java.util.random.RandomGenerator;

public final class ClientPRFSession {
    public static ClientPRFSession from(char[] pass) {
        return new ClientPRFSession(pass, VoteChallenges.RANDOM);
    }

    public static ClientPRFSession from(ClientPRFSession old, ServerPRFPresent answer, char[] pass) {
        try {
            return new ClientPRFSession(old, answer, pass);
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
        var passBytes = Unpooled.buffer(64);
        BLS12381.pbkdf2(pass, "password", passBytes, 64);
        this.r = BLS12381.randomToField(rng);
        this.pPass = BLS12381.hashToPoint(passBytes, 64);
        passBytes.setZero(0, 64);
        this.sMaster = new BIG(0);
    }

    ClientPRFSession(ClientPRFSession old, ServerPRFPresent answer, char[] pass) {
        this.r = old.r;
        this.pPass = old.pPass;
        var cipherKeyBytes = Unpooled.buffer(32);
        BLS12381.fieldToBytes(BLS12381.hashToScalar(pass, answer.n.mul(BLS12381.fieldInverse(old.r))), cipherKeyBytes);
        var masterBytes = answer.ePass.decrypt(ByteBufUtil.getBytes(cipherKeyBytes));
        this.sMaster = BLS12381.secretKeyToField(Unpooled.wrappedBuffer(masterBytes));
    }

    ClientPRFSession(ClientPRFSession old, ServerPRFPresent answer, ShortMnemonic recoveryKey) {
        this.r = old.r;
        this.pPass = old.pPass;
        var cipherKeyBytes = Unpooled.buffer(32);
        BLS12381.pbkdf2(recoveryKey.chars(), "mnemonic", cipherKeyBytes, 32);
        var masterBytes = answer.ePass.decrypt(ByteBufUtil.getBytes(cipherKeyBytes));
        this.sMaster = BLS12381.secretKeyToField(Unpooled.wrappedBuffer(masterBytes));
    }

    ClientPRFSession(ByteBuf input) {
        this.r = BLS12381.secretKeyToField(input);
        this.pPass = BLS12381.signatureToPoint(input);
        this.sMaster = BLS12381.bytesToField(input);
    }
}

