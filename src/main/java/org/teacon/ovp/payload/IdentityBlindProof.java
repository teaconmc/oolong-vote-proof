/*
 * Copyright (C) 2026 TeaConMC <contact@teacon.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

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

    public IdentitySignature signature() {
        return this.signature;
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

    IdentityBlindProof(VoteClientContext context, UUID work,
                       VoteInformation info, IdentitySignature signature, RandomGenerator rng) {
        // basic info
        this.work = work;
        this.id = new IdentityDerivation(context, work);
        this.info = info;
        // blind signature
        this.signature = new IdentitySignature(signature, rng);
        // q (G1 point) and r (pairing)
        var r = BLS12381.randomToField(rng);
        var buf = Unpooled.buffer(256 + signature.rolesByteCount + 256);
        buf.writeLong(work.getMostSignificantBits()).writeLong(work.getLeastSignificantBits());
        var qPoint = BLS12381.hashToPoint(buf.slice(), 128 / Byte.SIZE).mul(r);
        var rPairing = BLS12381.pairing(this.signature.a, context.serverKey.y.mul(r));
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
        ByteBuf output = buf.clear();
        BLS12381.pointToPubKey(context.serverKey.w, output);
        BLS12381.pointToPubKey(context.serverKey.x, output);
        BLS12381.pointToPubKey(context.serverKey.y, output);
        BLS12381.fieldToBytes(this.d, buf);
        BLS12381.pointToSignature(qPoint, buf);
        BLS12381.pairingToIndexBE(rPairing, buf);
        this.c = BLS12381.hashToScalar(buf, buf.readableBytes());
        // z (scalar)
        this.z = BLS12381.fieldMultiplyAdd(this.c, context.secretKey.core(), r);
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
