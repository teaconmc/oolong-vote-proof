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
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.util.BLS12381;

import java.security.GeneralSecurityException;
import java.security.SignatureException;

public final class ServerPRFAbsent {
    public static ServerPRFAbsent load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new ServerPRFAbsent(input);
        } catch (RuntimeException e) {
            throw new SignatureException("invalid server prf evaluation", e);
        }
    }

    public void dump(ByteBuf output) {
        BLS12381.pointToSignature(this.n, output);
    }

    final ECP n;

    ServerPRFAbsent(ServerSecretKey serverSecret, ClientPRFRequest request) {
        this.n = request.m.mul(serverSecret.v);
    }

    ServerPRFAbsent(ServerPRFPresent answer) {
        this.n = answer.n;
    }

    ServerPRFAbsent(ByteBuf input) {
        this.n = BLS12381.signatureToPoint(input);
    }
}
