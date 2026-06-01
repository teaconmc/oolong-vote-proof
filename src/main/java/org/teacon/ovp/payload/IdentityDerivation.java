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

import com.google.common.hash.HashCode;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.teacon.ovp.miracl.core.BLS12381.CONFIG_BIG;
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.miracl.core.BLS12381.ECP2;
import org.teacon.ovp.util.BLS12381;

import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.util.UUID;

public final class IdentityDerivation {
    public static IdentityDerivation load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new IdentityDerivation(input);
        } catch (RuntimeException e) {
            throw new SignatureException("invalid server signature", e);
        }
    }

    public HashCode index() {
        var buf = Unpooled.buffer(CONFIG_BIG.MODBYTES * 12);
        BLS12381.pairingToIndexBE(BLS12381.pairing(this.id, ECP2.generator()), buf);
        return HashCode.fromBytes(ByteBufUtil.getBytes(buf, 0, buf.readableBytes()));
    }

    public void dump(ByteBuf output) {
        BLS12381.pointToSignature(this.id, output);
    }

    final ECP id;

    IdentityDerivation(VoteClientContext context, UUID work) {
        var workLength = 128 / Byte.SIZE;
        var buf = Unpooled.buffer(workLength);
        buf.writeLong(work.getMostSignificantBits()).writeLong(work.getLeastSignificantBits());
        this.id = BLS12381.hashToPoint(buf, workLength).mul(context.secretKey.core());
    }

    IdentityDerivation(ByteBuf input) {
        this.id = BLS12381.signatureToPoint(input);
    }
}
