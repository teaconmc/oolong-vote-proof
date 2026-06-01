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

package org.teacon.ovp.util;

import io.netty.buffer.ByteBufUtil;

import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

public final class WorkInformation {
    private static final Pattern ALIAS_PATTERN = Pattern.compile("#[a-z0-9._-]+");

    private final UUID uuid;
    private final String desc;
    private final String alias;

    public WorkInformation(UUID uuid, String desc) {
        this.uuid = uuid;
        this.desc = desc;
        if (this.desc.isEmpty()) {
            throw new IllegalArgumentException("empty desc");
        }
        var descLength = ByteBufUtil.utf8Bytes(this.desc);
        if (descLength >= 0x200000) {
            throw new IllegalArgumentException("too many bytes of desc: " + descLength + " >= " + 0x200000);
        }
        this.alias = "";
    }

    public WorkInformation(UUID uuid, String desc, String alias) {
        this.uuid = uuid;
        this.desc = desc;
        if (this.desc.isEmpty()) {
            throw new IllegalArgumentException("empty desc");
        }
        var descLength = ByteBufUtil.utf8Bytes(this.desc);
        if (descLength >= 0x200000) {
            throw new IllegalArgumentException("too many bytes of desc: " + descLength + " >= " + 0x200000);
        }
        this.alias = alias;
        if (this.alias.isEmpty()) {
            throw new IllegalArgumentException("empty alias");
        }
        if (!ALIAS_PATTERN.matcher(this.alias).matches()) {
            throw new IllegalArgumentException("invalid alias: " + this.alias);
        }
    }

    public UUID uuid() {
        return this.uuid;
    }

    public String desc() {
        return this.desc;
    }

    public Optional<String> alias() {
        return this.alias.isEmpty() ? Optional.empty() : Optional.of(this.alias);
    }
}
