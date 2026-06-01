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

import io.netty.buffer.ByteBuf;
import org.teacon.ovp.miracl.core.BLS12381.BIG;
import org.teacon.ovp.util.BLS12381;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.function.Supplier;

public final class ServerSecretKey {
    public static ServerSecretKey load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new ServerSecretKey(input);
        } catch (RuntimeException e) {
            throw new InvalidKeyException("invalid server secret key", e);
        }
    }

    public void dump(ByteBuf output) {
        BLS12381.fieldToSecretKey(this.v, output);
        BLS12381.fieldToSecretKey(this.w, output);
        BLS12381.fieldToSecretKey(this.x, output);
        BLS12381.fieldToSecretKey(this.y, output);
    }

    final BIG v;
    final BIG w;
    final BIG x;
    final BIG y;

    ServerSecretKey(Supplier<BIG> v, VoteServerContext context) {
        this.v = new BIG(v.get());
        this.w = new BIG(context.w);
        this.x = new BIG(context.x);
        this.y = new BIG(context.y);
    }

    ServerSecretKey(ByteBuf input) {
        this.v = BLS12381.secretKeyToField(input);
        this.w = BLS12381.secretKeyToField(input);
        this.x = BLS12381.secretKeyToField(input);
        this.y = BLS12381.secretKeyToField(input);
    }
}
