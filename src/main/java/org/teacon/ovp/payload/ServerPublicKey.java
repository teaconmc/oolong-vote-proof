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
import org.teacon.ovp.miracl.core.BLS12381.ECP2;
import org.teacon.ovp.util.BLS12381;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

public final class ServerPublicKey {
    public static ServerPublicKey load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new ServerPublicKey(input);
        } catch (RuntimeException e) {
            throw new InvalidKeyException("invalid server public key", e);
        }
    }

    public void dump(ByteBuf output) {
        BLS12381.pointToPubKey(this.v, output);
        BLS12381.pointToPubKey(this.w, output);
        BLS12381.pointToPubKey(this.x, output);
        BLS12381.pointToPubKey(this.y, output);
    }

    final ECP2 v;
    final ECP2 w;
    final ECP2 x;
    final ECP2 y;

    ServerPublicKey(ServerSecretKey sk) {
        var g = ECP2.generator();
        this.v = g.mul(sk.v);
        this.w = g.mul(sk.w);
        this.x = g.mul(sk.x);
        this.y = g.mul(sk.y);
    }

    ServerPublicKey(ByteBuf input) {
        this.v = BLS12381.keyValidate(input);
        this.w = BLS12381.keyValidate(input);
        this.x = BLS12381.keyValidate(input);
        this.y = BLS12381.keyValidate(input);
    }
}
