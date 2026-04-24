package org.teacon.ovp.payload;

import com.google.common.collect.ImmutableList;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.teacon.ovp.miracl.core.BLS12381.BIG;
import org.teacon.ovp.util.BLS12381;
import org.teacon.ovp.util.TagReference;
import org.teacon.ovp.util.VoteInformation;

import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.util.Objects;
import java.util.TreeMap;
import java.util.UUID;
import java.util.random.RandomGenerator;

public final class IdentityBlindProof {

    public static IdentityBlindProof from(ClientSecretKey clientSecret, ServerPublicKey serverPublic,
                                          UUID work, VoteInformation info, IdentitySignature signature) {
        return new IdentityBlindProof(clientSecret, serverPublic, work, info, signature, VoteChallenges.RANDOM);
    }

    public static IdentityBlindProof load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new IdentityBlindProof(input);
        } catch (RuntimeException e) {
            throw new SignatureException("invalid server signature", e);
        }
    }

    public UUID work() {
        return this.work;
    }

    public IdentityDerivation id() {
        return this.id;
    }

    public VoteInformation info() {
        return this.info;
    }

    public void dump(ByteBuf buf) {
        buf.writeLong(this.work.getMostSignificantBits()).writeLong(this.work.getLeastSignificantBits());
        this.id.dump(buf);
        for (var entry : this.info.levels().entrySet()) {
            buf.writeShort(entry.getValue().magic());
            BLS12381.stringToBytes(false, entry.getKey().toString(), buf);
        }
        buf.writeShort(-this.info.comments().size()/* 0x0000, 0xFFF0 ~ 0xFFFF */);
        for (var comment : this.info.comments()) {
            BLS12381.stringToBytes(true, comment, buf);
        }
        this.signature.dump(buf);
        BLS12381.fieldToBytes(this.c, buf);
        BLS12381.fieldToBytes(this.z, buf);
    }

    final UUID work;
    final IdentityDerivation id;
    final VoteInformation info;
    final IdentitySignature signature;
    final BIG d;
    final BIG c;
    final BIG z;

    IdentityBlindProof(ClientSecretKey clientSecret, ServerPublicKey serverPublic,
                       UUID work, VoteInformation info, IdentitySignature signature, RandomGenerator rng) {
        // basic info
        this.work = work;
        this.id = new IdentityDerivation(work, clientSecret);
        this.info = info;
        // blind signature
        this.signature = new IdentitySignature(signature, rng);
        // q (G1 point) and r (pairing)
        var r = BLS12381.randomToField(rng);
        var buf = Unpooled.buffer(256 + signature.rolesByteCount + 256);
        buf.writeLong(work.getMostSignificantBits()).writeLong(work.getLeastSignificantBits());
        var qPoint = BLS12381.hashToPoint(buf.slice(), 128 / Byte.SIZE).mul(r);
        var rPairing = BLS12381.pairing(this.signature.a, serverPublic.y.mul(r));
        // role hash (scalar) and d (scalar)
        this.id.dump(buf);
        for (var entry : info.levels().entrySet()) {
            buf.writeShort(entry.getValue().magic());
            BLS12381.stringToBytes(false, entry.getKey().toString(), buf);
        }
        buf.writeShort(-info.comments().size()/* 0x0000, 0xFFF0 ~ 0xFFFF */);
        for (var comment : info.comments()) {
            BLS12381.stringToBytes(true, comment, buf);
        }
        this.signature.dump(buf);
        this.d = BLS12381.hashToScalar(buf, buf.readableBytes());
        // c (scalar)
        serverPublic.dump(buf.clear());
        BLS12381.fieldToBytes(this.d, buf);
        BLS12381.pointToSignature(qPoint, buf);
        BLS12381.pairingToIndexBE(rPairing, buf);
        this.c = BLS12381.hashToScalar(buf, buf.readableBytes());
        // z (scalar)
        this.z = BLS12381.fieldMultiplyAdd(this.c, clientSecret.s, r);
    }

    IdentityBlindProof(ByteBuf input) {
        // work
        var workIndex = input.readerIndex();
        this.work = new UUID(input.readLong(), input.readLong());
        // id
        this.id = new IdentityDerivation(input);
        // info
        var infoLevelMap = new TreeMap<TagReference, VoteInformation.Level>();
        var magic = input.readShort();
        while (true) {
            var level = VoteInformation.Level.fromMagic(magic);
            if (level.isEmpty()) {
                break;
            }
            var key = BLS12381.bytesToString(false, input);
            var fresh = Objects.isNull(infoLevelMap.put(new TagReference(key), level.get()));
            if (!fresh || !infoLevelMap.lastKey().toString().equals(key)) {
                throw new IllegalArgumentException("unsorted tag references");
            }
            magic = input.readShort();
        }
        if (magic < (short) 0xFFF0 || magic > (short) 0) {
            throw new IllegalArgumentException("unknown magic: 0x%04X".formatted(magic));
        }
        var infoCommentCount = -magic;
        var infoCommentBuilder = ImmutableList.<String>builderWithExpectedSize(infoCommentCount);
        for (var i = 0; i < infoCommentCount; ++i) {
            var comment = BLS12381.bytesToString(true, input);
            infoCommentBuilder.add(comment);
        }
        this.info = new VoteInformation(infoLevelMap, infoCommentBuilder.build());
        // signature
        this.signature = new IdentitySignature(input);
        // d
        var dLength = input.readerIndex() - workIndex;
        this.d = BLS12381.hashToScalar(input.slice(workIndex, dLength), dLength);
        // c (scalar), z (scalar)
        this.c = BLS12381.bytesToField(input);
        this.z = BLS12381.bytesToField(input);
    }
}
