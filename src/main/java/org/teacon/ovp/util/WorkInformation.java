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
