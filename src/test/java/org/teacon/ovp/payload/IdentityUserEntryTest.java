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

import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.util.BLS12381;
import org.teacon.ovp.util.TagReference;

import java.util.TreeSet;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class IdentityUserEntryTest {
    @Test
    public void constructor_dump_load_and_defensive_copy_work() throws Exception {
        var uuid = new UUID(1L, 2L);
        var envelopeBytes = new byte[224];
        for (var i = 0; i < envelopeBytes.length; ++i) {
            envelopeBytes[i] = (byte) i;
        }
        var overrideBytes = Unpooled.buffer();
        BLS12381.pointToSignature(ECP.generator(), overrideBytes);
        overrideBytes.writeBytes(envelopeBytes);
        var override = new ClientPRFOverride(overrideBytes);

        var roles = new TreeSet<TagReference>();
        roles.add(new TagReference("alpha", "a"));
        var entry = new IdentityUserEntry(uuid, override, roles);

        roles.add(new TagReference("beta", "b"));

        assertEquals(uuid, entry.uuid());
        assertEquals(BLS12381.encodeEnvelope(Unpooled.wrappedBuffer(envelopeBytes)), entry.envelope());
        assertEquals(1, entry.roles().size());
        assertEquals(new TagReference("alpha", "a"), entry.roles().first());
        assertThrows(UnsupportedOperationException.class, () -> entry.roles().add(new TagReference("gamma", "c")));

        var dumpedCommit = Unpooled.buffer();
        var overrideCommit = Unpooled.buffer();
        BLS12381.pointToSignature(entry.commit, dumpedCommit);
        BLS12381.pointToSignature(override.s, overrideCommit);
        assertArrayEquals(dumpedCommit.array(), overrideCommit.array());

        var dumped = Unpooled.buffer();
        entry.dump(dumped);
        var loaded = IdentityUserEntry.load(dumped);

        var loadedCommit = Unpooled.buffer();
        BLS12381.pointToSignature(loaded.commit, loadedCommit);
        assertArrayEquals(dumpedCommit.array(), loadedCommit.array());
        assertEquals(entry.uuid(), loaded.uuid());
        assertEquals(entry.envelope(), loaded.envelope());
        assertEquals(entry.roles(), loaded.roles());
    }
}
