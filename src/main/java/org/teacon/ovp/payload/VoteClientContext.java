package org.teacon.ovp.payload;

import com.google.common.base.Preconditions;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.teacon.ovp.miracl.core.BLS12381.BIG;
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.util.BLS12381;
import org.teacon.ovp.util.ShortMnemonic;

import java.io.IOException;
import java.nio.CharBuffer;
import java.util.function.Consumer;
import java.util.random.RandomGenerator;

public final class VoteClientContext {
    public static VoteClientContext create(ServerPublicKey key) {
        return new VoteClientContext(key, RandomGenerator.of("SecureRandom"));
    }

    final ServerPublicKey serverKey;
    final ByteBuf serverKeyBytes;
    final RandomGenerator rng;
    final ByteBuf password;
    final ECP passwordHash;
    final BIG randomScalar;
    final ECP passwordPRF;
    final BIG secretKey;

    VoteClientContext(ServerPublicKey key, RandomGenerator generator) {
        this.serverKey = key;
        this.serverKeyBytes = Unpooled.buffer(48 * 8);
        key.dump(this.serverKeyBytes);
        this.rng = generator;
        this.password = Unpooled.buffer();
        this.passwordHash = BLS12381.hashToPoint(this.password, 0);
        this.randomScalar = BLS12381.randomToField(generator);
        this.passwordPRF = ECP.generator().mul(new BIG(0));
        this.secretKey = new BIG(0);
    }

    public VoteClientContext readPassword(char[] password) throws IOException {
        var wrapped = CharBuffer.wrap(password);
        var bytes = ByteBufUtil.utf8Bytes(wrapped);
        if (bytes != password.length) {
            throw new IOException("non-ascii password key");
        }
        var capacity = this.password.capacity();
        var ensured = bytes == 0 ? 0 : 1 << (Integer.SIZE - Integer.numberOfLeadingZeros(bytes - 1));
        if (capacity == ensured) {
            this.password.setZero(this.password.writerIndex(), capacity).writerIndex(0);
        } else {
            this.password.setZero(0, capacity).writerIndex(0).capacity(ensured);
        }
        ByteBufUtil.writeAscii(this.password, wrapped);
        this.passwordHash.copy(BLS12381.hashToPoint(this.password.slice(0, bytes), bytes));
        this.randomScalar.copy(BLS12381.randomToField(this.rng));
        this.passwordPRF.mul(new BIG(0));
        return this;
    }

    public VoteClientContext readSecretKey(ClientSecretKey key) {
        this.password.setZero(0, this.password.capacity()).writerIndex(0).capacity(0);
        this.passwordHash.copy(BLS12381.hashToPoint(this.password, 0));
        this.randomScalar.copy(BLS12381.randomToField(this.rng));
        this.passwordPRF.mul(new BIG(0));
        this.secretKey.copy(key.s);
        return this;
    }

    public VoteClientContext readPasswordPRF(ServerPRFAbsent resp) throws IOException {
        var validated = VoteChallenges.validate(this, resp);
        if (!validated) {
            throw new IOException("mismatched server response and client request");
        }
        this.passwordPRF.copy(resp.n.mul(BLS12381.fieldInverse(this.randomScalar)));
        return this;
    }

    public VoteClientContext readSecretKeyByPassword(ServerPRFPresent resp) throws IOException {
        try {
            var diff = resp.n.mul(BLS12381.fieldInverse(this.randomScalar));
            diff.sub(this.passwordPRF);
            Preconditions.checkArgument(diff.is_infinity());
            var seedKey = Unpooled.buffer(0);
            this.hashToPasswordSeed(seedKey);
            var envelope = Unpooled.wrappedBuffer(resp.ePass);
            var ctx = this.serverKeyBytes.slice();
            this.secretKey.copy(BLS12381.decodeEnvelope(envelope, ctx, ctx.readableBytes(), seedKey));
            return this;
        } catch (RuntimeException e) {
            throw new IOException("malformed resp format or invalid password", e);
        }
    }

    public VoteClientContext readSecretKeyByMnemonic(ServerPRFPresent resp, ShortMnemonic mnemonic) throws IOException {
        try {
            var seedKey = Unpooled.buffer(0);
            this.hashToMnemonicSeed(mnemonic, seedKey);
            var envelope = Unpooled.wrappedBuffer(resp.eMnem);
            var ctx = this.serverKeyBytes.slice();
            this.secretKey.copy(BLS12381.decodeEnvelope(envelope, ctx, ctx.readableBytes(), seedKey));
            return this;
        } catch (RuntimeException e) {
            throw new IOException("malformed resp format or invalid mnemonic", e);
        }
    }

    public VoteClientContext dropSecretKeyAndPassword() {
        this.password.setZero(0, this.password.capacity()).writerIndex(0).capacity(0);
        this.passwordHash.copy(BLS12381.hashToPoint(this.password, 0));
        this.randomScalar.copy(BLS12381.randomToField(this.rng));
        this.passwordPRF.mul(new BIG(0));
        this.secretKey.zero();
        return this;
    }

    public boolean holdEmptySecretKey() {
        return this.secretKey.nbits() == 0;
    }

    public boolean holdEmptyPassword() {
        return this.password.writerIndex() == 0;
    }

    public ClientPRFRequest makePRFRequest() {
        return new ClientPRFRequest(this);
    }

    public ClientPRFOverride makePRFOverride(Consumer<ShortMnemonic> mnemonicConsumer) throws IOException {
        // point commit
        var key = new ClientSecretKey(this);
        this.secretKey.copy(key.s);
        // prepare salt
        var saltBytes = new byte[32];
        this.rng.nextBytes(saltBytes);
        var salt = Unpooled.wrappedBuffer(saltBytes);
        // prepare mnemonic
        var mnemonic = new ShortMnemonic(this.rng);
        mnemonicConsumer.accept(mnemonic);
        // generate seed keys
        var seedKey = Unpooled.buffer(0);
        this.hashToMnemonicSeed(mnemonic, seedKey);
        this.hashToPasswordSeed(seedKey);
        // write envelope bytes
        var envelopeBytes = new byte[224];
        var ctx = this.serverKeyBytes.slice();
        var eMnem = Unpooled.wrappedBuffer(envelopeBytes, 96, 128).writerIndex(0);
        BLS12381.encodeEnvelope(this.secretKey, ctx, ctx.readableBytes(), salt, seedKey, eMnem);
        var ePass = Unpooled.wrappedBuffer(envelopeBytes, 0, 128).writerIndex(0);
        BLS12381.encodeEnvelope(this.secretKey, ctx.readerIndex(0), ctx.readableBytes(), salt.readerIndex(0), seedKey, ePass);
        // construct override
        return new ClientPRFOverride(key, envelopeBytes);
    }

    public ServerPublicKey makeServerKey() {
        return this.serverKey;
    }

    public ClientSecretKey makeSecretKey() throws IOException {
        if (this.secretKey.nbits() == 0) {
            throw new IOException("uninitialized client secret key");
        }
        return new ClientSecretKey(this);
    }

    private void hashToPasswordSeed(ByteBuf output) throws IOException {
        var seedHashInputSize = this.password.writerIndex() + 48;
        var bufferCapacity = Math.max(seedHashInputSize, 64 + 32);
        var offset = output.ensureWritable(bufferCapacity).writerIndex();
        try {
            var seedHashInput = output.slice(offset, seedHashInputSize).writerIndex(0);
            seedHashInput.writeBytes(this.password.slice());
            if (this.passwordPRF.is_infinity()) {
                throw new IOException("uninitialized password prf result");
            }
            BLS12381.pointToSignature(this.passwordPRF, seedHashInput);
            var seedHash = BLS12381.hashToScalar(seedHashInput, seedHashInputSize);
            var seedInput = output.slice(offset + 64, 32).writerIndex(0);
            BLS12381.fieldToBytes(seedHash, seedInput);
            var seedKey = output.slice(offset, 64).writerIndex(0);
            BLS12381.pbkdf2(seedInput, 32, "password", false, seedKey, 64);
        } finally {
            output.setZero(offset + 64, bufferCapacity - 64);
            output.writerIndex(offset + 64);
        }
    }

    private void hashToMnemonicSeed(ShortMnemonic mnemonic, ByteBuf output) {
        var chars = mnemonic.chars();
        var bufferCapacity = 64 + chars.remaining();
        var offset = output.ensureWritable(bufferCapacity).writerIndex();
        try {
            var seedInput = output.slice(offset + 64, chars.remaining()).writerIndex(0);
            ByteBufUtil.writeAscii(seedInput, chars);
            var seedKey = output.slice(offset, 64).writerIndex(0);
            BLS12381.pbkdf2(seedInput, chars.remaining(), "mnemonic", false, seedKey, 64);
        } finally {
            output.setZero(offset + 64, bufferCapacity - 64);
            output.writerIndex(offset + 64);
        }
    }
}
