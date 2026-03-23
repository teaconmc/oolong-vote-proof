package org.teacon.ovp.util;

import org.junit.jupiter.api.Test;

import java.util.*;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

public final class VoteInformationTest {
    @Test
    public void constructor_accessors_copy_inputs_and_return_immutable_sorted_views() {
        var commentsIn = new ArrayList<>(List.of("first", "second"));
        var levelsIn = new HashMap<TagReference, VoteInformation.Level>();

        var k1 = new TagReference("b", "x");
        var k2 = new TagReference("a", "z");
        var k3 = new TagReference("a", "a");
        levelsIn.put(k1, VoteInformation.Level.ONE);
        levelsIn.put(k2, VoteInformation.Level.TWO);
        levelsIn.put(k3, VoteInformation.Level.THREE_HALF);

        var info = new VoteInformation(levelsIn, commentsIn);

        commentsIn.add("third");
        levelsIn.put(new TagReference("c", "y"), VoteInformation.Level.FIVE);

        assertEquals(List.of("first", "second"), info.comments());
        var expectedKeys = List.of("a:a", "a:z", "b:x");
        var actualKeys = info.levels().keySet().stream().map(TagReference::toString).toList();
        assertEquals(expectedKeys, actualKeys);

        assertThrows(UnsupportedOperationException.class, () -> info.comments().add("nope"));
        assertThrows(UnsupportedOperationException.class, () -> info.levels().put(k1, VoteInformation.Level.FOUR));
    }

    @Test
    public void constructor_rejects_invalid_comments() {
        var tooMany = IntStream.range(0, 17).mapToObj(i -> "c" + i).toList();
        var ex1 = assertThrows(IllegalArgumentException.class, () -> new VoteInformation(Map.of(), tooMany));
        assertTrue(ex1.getMessage().contains("too many comments"));

        var empty = List.of("ok", "", "ok2");
        var ex2 = assertThrows(IllegalArgumentException.class, () -> new VoteInformation(Map.of(), empty));
        assertTrue(ex2.getMessage().contains("empty comment"));
        assertTrue(ex2.getMessage().contains("comments[1]"));

        var tooLong = "a".repeat(0x200000);
        var ex3 = assertThrows(IllegalArgumentException.class, () -> new VoteInformation(Map.of(), List.of(tooLong)));
        assertTrue(ex3.getMessage().contains("too many bytes"));
    }

    @Test
    public void level_magic_and_fromMagic_round_trip_for_all_values_and_unknown_is_empty() {
        var seen = new HashSet<Short>();
        for (var level : VoteInformation.Level.values()) {
            assertTrue(seen.add(level.magic()), "duplicate magic: " + level);
            assertEquals(Optional.of(level), VoteInformation.Level.fromMagic(level.magic()));
        }
        assertEquals(Optional.empty(), VoteInformation.Level.fromMagic((short) 0));
    }
}
