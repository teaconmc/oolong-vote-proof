package org.teacon.ovp.payload;

import com.google.common.hash.HashCode;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.teacon.ovp.miracl.core.BLS12381.BIG;
import org.teacon.ovp.storage.DBService;
import org.teacon.ovp.util.BLS12381;

import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.random.RandomGenerator;

public final class VoteServerContext {

    public static VoteServerContext create(char[] seed, DBService service) {
        return new VoteServerContext(seed, service, RandomGenerator.of("SecureRandom"));
    }

    // constructed initially
    final RandomGenerator rng;
    final DBService service;
    final char[] seed;
    final BIG w;
    final BIG x;
    final BIG y;

    VoteServerContext(char[] seed, DBService service, RandomGenerator generator) {
        this.rng = generator;
        this.service = service;
        this.seed = seed.clone();
        this.w = this.makeSaltedSecret("role-key", Unpooled.EMPTY_BUFFER, 0);
        this.x = this.makeSaltedSecret("base-key", Unpooled.EMPTY_BUFFER, 0);
        this.y = this.makeSaltedSecret("bind-key", Unpooled.EMPTY_BUFFER, 0);
    }

    public ServerSecretKey makeSecretKey(UUID uuid) {
        var salt = "id-" + uuid + "-oprf-key";
        return new ServerSecretKey(() -> this.makeSaltedSecret(salt, Unpooled.EMPTY_BUFFER, 0), this);
    }

    public ServerPublicKey makePublicKey(UUID uuid) {
        return new ServerPublicKey(this.makeSecretKey(uuid));
    }

    public ServerPRFAbsent makePRFAbsent(UUID uuid, ClientPRFRequest request) {
        return new ServerPRFAbsent(this.makeSecretKey(uuid), request);
    }

    public CompletionStage<ServerPRFPresent> makePRFPresent(UUID uuid, ClientPRFRequest request) {
        return this.service.fetchAccount(uuid).thenApply(account -> {
            var fakeBytes = Unpooled.buffer(32 * 5);
            var v = this.makeSaltedSecret("id-" + uuid + "-fake-key", fakeBytes, 32 * 5);
            try {
                var fakeKey = new ServerSecretKey(() -> v, this);
                var fakeAbsent = new ServerPRFAbsent(fakeKey, request);
                var realAbsent = this.makePRFAbsent(uuid, request);
                var absent = account.isPresent() ? realAbsent : fakeAbsent;
                var fakeEnvelope = this.makeFakeEnvelope(new ServerPublicKey(fakeKey), fakeBytes);
                var envelope = account.map(IdentityUserEntry::envelope).orElse(fakeEnvelope);
                return new ServerPRFPresent(absent, envelope);
            } finally {
                fakeBytes.setZero(0, fakeBytes.capacity());
            }
        });
    }

    public CompletionStage<IdentitySignature> makeSignature(UUID uuid, ClientPointCommit pointCommit) {
        return this.service.fetchAccount(uuid).thenApply(account -> {
            var entry = account.orElseThrow(() -> new IllegalArgumentException("missing identity user entry"));
            if (!entry.commit.equals(pointCommit.s)) {
                throw new IllegalArgumentException("mismatched client point commit");
            }
            return new IdentitySignature(this.makeSecretKey(uuid), pointCommit, entry.roles(), this.rng);
        });
    }

    public CompletionStage<Void> readBlindProof(IdentityBlindProof proof) {
        return this.service.fetchRevocations().thenCompose(revocations -> {
            var index = proof.id().index();
            if (revocations.stream().anyMatch(r -> this.makeWorkIndex(r, proof.work).equals(index))) {
                return CompletableFuture.failedStage(new IllegalArgumentException("revoked identity blind proof"));
            }
            if (!VoteChallenges.validate(this, proof)) {
                return CompletableFuture.failedStage(new IllegalArgumentException("invalid identity blind proof"));
            }
            return this.service.storeVote(proof);
        });
    }

    public CompletionStage<Void> readRevocation(UUID uuid, ClientRevocation revocation) {
        return this.service.fetchAccount(uuid).thenCompose(account -> {
            var entry = account.orElseThrow(() -> new IllegalArgumentException("missing identity user entry"));
            if (!VoteChallenges.validate(new ClientPointCommit(entry), revocation)) {
                return CompletableFuture.failedStage(new IllegalArgumentException("mismatched client revocation"));
            }
            var store = this.service.storeRevocation(revocation);
            return store.thenCompose(v -> this.service.fetchWorks().thenCompose(works -> {
                var indexes = works.stream().map(w -> this.makeWorkIndex(revocation, w.uuid())).toList();
                return this.service.purgeVotes(indexes).thenApply(i -> null);
            }));
        });
    }

    private BIG makeSaltedSecret(String salt, ByteBuf extraOutput, int extraLength) {
        var result = new BIG(0);
        var outputLength = 96 + extraLength;
        while (result.nbits() == 0) {
            var seed = Unpooled.copiedBuffer(CharBuffer.wrap(this.seed), StandardCharsets.UTF_8);
            var derived = Unpooled.buffer(outputLength);
            try {
                BLS12381.pbkdf2(seed.readerIndex(0), seed.readableBytes(), salt, derived, outputLength);
                result.copy(BLS12381.hashToScalar(derived.slice(0, 96), 96));
                if (result.nbits() != 0 && extraLength > 0) {
                    extraOutput.writeBytes(derived, 96, extraLength);
                }
            } finally {
                seed.setZero(0, seed.capacity());
                derived.setZero(0, derived.capacity());
            }
            outputLength += 32;
        }
        return result;
    }

    private String makeFakeEnvelope(ServerPublicKey publicKey, ByteBuf fakeBytes) {
        // ctx
        var s = new BIG(0);
        var ctx = Unpooled.buffer(384);
        publicKey.dump(ctx);
        var salt = fakeBytes.readSlice(32);
        var seedMnem = fakeBytes.readSlice(64);
        var seedPass = fakeBytes.readSlice(64);
        // write envelope bytes
        var envelopeBytes = new byte[224];
        var eMnem = Unpooled.wrappedBuffer(envelopeBytes, 96, 128).writerIndex(0);
        BLS12381.encodeEnvelopePart(s, ctx, ctx.readableBytes(), salt, seedMnem, eMnem);
        var ePass = Unpooled.wrappedBuffer(envelopeBytes, 0, 128).writerIndex(0);
        BLS12381.encodeEnvelopePart(s, ctx.readerIndex(0), ctx.readableBytes(), salt.readerIndex(0), seedPass, ePass);
        // serialize
        return BLS12381.encodeEnvelope(Unpooled.wrappedBuffer(envelopeBytes));
    }

    private HashCode makeWorkIndex(ClientRevocation revocation, UUID work) {
        var workBytes = Unpooled.buffer(16);
        workBytes.writeLong(work.getMostSignificantBits()).writeLong(work.getLeastSignificantBits());
        var pairing = BLS12381.pairing(BLS12381.hashToPoint(workBytes, 16), revocation.c);
        var output = Unpooled.buffer(32 * 12);
        BLS12381.pairingToIndexBE(pairing, output);
        return HashCode.fromBytes(ByteBufUtil.getBytes(output, 0, output.readableBytes()));
    }
}
