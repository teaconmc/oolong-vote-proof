package org.teacon.ovp.util;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSortedMap;
import com.google.common.collect.Ordering;
import io.netty.buffer.ByteBufUtil;

import java.util.*;

public final class VoteInformation {
    private final ImmutableList<String> comments;
    private final ImmutableSortedMap<TagReference, Level> levels;

    public VoteInformation(Map<TagReference, Level> levels, List<String> comments) {
        var commentSize = comments.size();
        if (commentSize > 16) {
            throw new IllegalArgumentException("too many comments: " + commentSize + " > 16");
        }
        for (var i = 0; i < commentSize; ++i) {
            var comment = comments.get(i);
            var len = ByteBufUtil.utf8Bytes(comment);
            if (len == 0) {
                throw new IllegalArgumentException("empty comment at comments[" + i + "]");
            }
            if (len >= 0x200000) {
                throw new IllegalArgumentException("too many bytes of comments[" + i + "]: " + len + " >= " + 0x200000);
            }
        }
        this.levels = ImmutableSortedMap.copyOf(levels, Ordering.natural());
        this.comments = ImmutableList.copyOf(comments);
    }

    public List<String> comments() {
        return this.comments;
    }

    public SortedMap<TagReference, Level> levels() {
        return this.levels;
    }

    public enum Level {
        ONE(0x3C00), ONE_HALF(0x3E00), TWO(0x4000),
        TWO_HALF(0x4100), THREE(0x4200), THREE_HALF(0x4300),
        FOUR(0x4400), FOUR_HALF(0x4480), FIVE(0x4500);

        private final short magic;

        Level(int magic) {
            this.magic = (short) magic;
        }

        public short magic() {
            return this.magic;
        }

        public static Optional<Level> fromMagic(short magic) {
            return Arrays.stream(Level.values()).filter(l -> l.magic == magic).findFirst();
        }
    }
}
