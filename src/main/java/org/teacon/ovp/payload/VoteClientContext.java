package org.teacon.ovp.payload;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.teacon.ovp.miracl.core.BLS12381.BIG;
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.util.BLS12381;
import org.teacon.ovp.util.ShortMnemonic;
import org.teacon.ovp.util.VoteInformation;

import java.io.IOException;
import java.nio.CharBuffer;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.random.RandomGenerator;

public final class VoteClientContext {
    public static VoteClientContext create(ServerPublicKey key) {
        return new VoteClientContext(key, RandomGenerator.of("SecureRandom"));
    }

    // constructed initially
    final ServerPublicKey serverKey;
    final ByteBuf serverKeyBytes;
    final RandomGenerator rng;

    // password related
    final ByteBuf password;
    final ECP passwordHash;
    final BIG randomScalar;

    // secretKey
    final BIG secretKey;

    VoteClientContext(ServerPublicKey key, RandomGenerator generator) {
        // initialize immutable context and shared buffers
        this.serverKey = key;
        this.serverKeyBytes = Unpooled.buffer(48 * 8);
        key.dump(this.serverKeyBytes);
        this.rng = generator;
        // initialize resettable client-side state
        this.password = Unpooled.buffer();
        this.passwordHash = BLS12381.hashToPoint(this.password, 0);
        this.randomScalar = BLS12381.randomToField(generator);
        this.secretKey = BLS12381.randomToField(generator);
    }

    public VoteClientContext readPassword(char[] password) throws IOException {
        // validate password is ASCII-only and get byte length
        var wrapped = CharBuffer.wrap(password);
        var bytes = ByteBufUtil.utf8Bytes(wrapped);
        if (bytes != password.length) {
            throw new IOException("non-ascii password key");
        }
        // resize or clear password buffer to a power-of-two capacity
        var capacity = this.password.capacity();
        var ensured = bytes == 0 ? 0 : 1 << (Integer.SIZE - Integer.numberOfLeadingZeros(bytes - 1));
        if (capacity == ensured) {
            this.password.setZero(this.password.writerIndex(), capacity).writerIndex(0);
        } else {
            this.password.setZero(0, capacity).writerIndex(0).capacity(ensured);
        }
        // refresh derived password-related state
        ByteBufUtil.writeAscii(this.password, wrapped);
        this.passwordHash.copy(BLS12381.hashToPoint(this.password.slice(0, bytes), bytes));
        this.randomScalar.copy(BLS12381.randomToField(this.rng));
        return this;
    }

    public VoteClientContext readSecretKey(ClientSecretKey key) {
        // clear password-derived state when importing an existing secret key
        this.password.setZero(0, this.password.capacity()).writerIndex(0).capacity(0);
        this.passwordHash.copy(BLS12381.hashToPoint(this.password, 0));
        this.randomScalar.copy(BLS12381.randomToField(this.rng));
        // commit imported secret key
        this.secretKey.copy(key.s);
        return this;
    }

    public VoteClientContext readSecretKeyByPassword(ServerPRFPresent resp) throws IOException {
        try {
            // verify server challenge response matches current request context
            var absent = new ServerPRFAbsent(resp);
            var validated = VoteChallenges.validate(this, absent);
            if (!validated) {
                throw new IOException("mismatched server response and client request");
            }
            // derive password seed key and decrypt password envelope
            var seedKey = Unpooled.buffer(0);
            this.hashToPasswordSeed(absent, seedKey);
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
            // verify server challenge response matches current request context
            var validated = VoteChallenges.validate(this, new ServerPRFAbsent(resp));
            if (!validated) {
                throw new IOException("mismatched server response and client request");
            }
            // derive mnemonic seed key and decrypt mnemonic envelope
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

    public VoteClientContext dropPasswordAndRotateSecretKey() {
        // wipe password and all password-derived state
        this.password.setZero(0, this.password.capacity()).writerIndex(0).capacity(0);
        this.passwordHash.copy(BLS12381.hashToPoint(this.password, 0));
        this.randomScalar.copy(BLS12381.randomToField(this.rng));
        // clear secret key material
        this.secretKey.copy(BLS12381.randomToField(this.rng));
        return this;
    }

    public boolean holdEmptyPassword() {
        return this.password.writerIndex() == 0;
    }

    public ServerPublicKey makeServerKey() {
        return this.serverKey;
    }

    public ClientSecretKey makeSecretKey() {
        return new ClientSecretKey(this);
    }

    public ClientPRFRequest makePRFRequest() {
        return new ClientPRFRequest(this);
    }

    public ClientPRFOverride makePRFOverride(ServerPRFAbsent resp, Consumer<ShortMnemonic> holder) throws IOException {
        // verify server challenge response matches current request context
        var validated = VoteChallenges.validate(this, resp);
        if (!validated) {
            throw new IOException("mismatched server response and client request");
        }
        // prepare salt
        var saltBytes = new byte[32];
        this.rng.nextBytes(saltBytes);
        var salt = Unpooled.wrappedBuffer(saltBytes);
        // prepare mnemonic
        var mnemonic = new ShortMnemonic(this.rng);
        holder.accept(mnemonic);
        // generate seed keys
        var seedKey = Unpooled.buffer(0);
        this.hashToMnemonicSeed(mnemonic, seedKey);
        this.hashToPasswordSeed(resp, seedKey);
        // write envelope bytes
        var secret = this.secretKey;
        var envelopeBytes = new byte[224];
        var ctx = this.serverKeyBytes.slice();
        var eMnem = Unpooled.wrappedBuffer(envelopeBytes, 96, 128).writerIndex(0);
        BLS12381.encodeEnvelope(secret, ctx, ctx.readableBytes(), salt, seedKey, eMnem);
        var ePass = Unpooled.wrappedBuffer(envelopeBytes, 0, 128).writerIndex(0);
        BLS12381.encodeEnvelope(secret, ctx.readerIndex(0), ctx.readableBytes(), salt.readerIndex(0), seedKey, ePass);
        // construct override
        return new ClientPRFOverride(this, envelopeBytes);
    }

    public ClientPointCommit makePointCommit() {
        return new ClientPointCommit(this);
    }

    public IdentityDerivation makeIdentityDerivation(UUID work) {
        return new IdentityDerivation(this, work);
    }

    public IdentityBlindProof makeIdentityBlindProof(UUID work, VoteInformation info, IdentitySignature sig) {
        return new IdentityBlindProof(this, work, info, sig, VoteChallenges.RANDOM);
    }

    public ClientRevocation makeRevocation() {
        return new ClientRevocation(this);
    }

    private void hashToPasswordSeed(ServerPRFAbsent resp, ByteBuf output) throws IOException {
        // reserve output space for seed key and transient hashing buffers
        var seedHashInputSize = this.password.writerIndex() + 48;
        var bufferCapacity = Math.max(seedHashInputSize, 64 + 32);
        var offset = output.ensureWritable(bufferCapacity).writerIndex();
        try {
            // hash password bytes and password PRF point into a scalar
            var seedHashInput = output.slice(offset, seedHashInputSize).writerIndex(0);
            seedHashInput.writeBytes(this.password.slice());
            BLS12381.pointToSignature(resp.n.mul(BLS12381.fieldInverse(this.randomScalar)), seedHashInput);
            var seedHash = BLS12381.hashToScalar(seedHashInput, seedHashInputSize);
            // run PBKDF2 over the scalar bytes to derive a 64-byte seed key
            var seedInput = output.slice(offset + 64, 32).writerIndex(0);
            BLS12381.fieldToBytes(seedHash, seedInput);
            var seedKey = output.slice(offset, 64).writerIndex(0);
            BLS12381.pbkdf2(seedInput, 32, "password", seedKey, 64);
        } finally {
            // wipe temporary bytes and keep only derived seed key in-place
            output.setZero(offset + 64, bufferCapacity - 64);
            output.writerIndex(offset + 64);
        }
    }

    private void hashToMnemonicSeed(ShortMnemonic mnemonic, ByteBuf output) {
        // reserve output space for seed key and transient mnemonic bytes
        var chars = mnemonic.chars();
        var bufferCapacity = 64 + chars.remaining();
        var offset = output.ensureWritable(bufferCapacity).writerIndex();
        try {
            // encode mnemonic chars and derive a 64-byte seed key via PBKDF2
            var seedInput = output.slice(offset + 64, chars.remaining()).writerIndex(0);
            ByteBufUtil.writeAscii(seedInput, chars);
            var seedKey = output.slice(offset, 64).writerIndex(0);
            BLS12381.pbkdf2(seedInput, chars.remaining(), "mnemonic", seedKey, 64);
        } finally {
            // wipe transient bytes and keep only derived seed key in-place
            output.setZero(offset + 64, bufferCapacity - 64);
            output.writerIndex(offset + 64);
        }
    }
}
