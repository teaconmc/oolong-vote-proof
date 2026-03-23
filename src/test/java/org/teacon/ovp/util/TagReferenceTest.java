package org.teacon.ovp.util;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public final class TagReferenceTest {
    @Test
    public void constructors_accessors_equals_and_hashCode_work_for_common_paths() {
        var ref1 = new TagReference("foo", "bar/baz");
        assertEquals("foo", ref1.namespace());
        assertEquals("bar/baz", ref1.path());
        assertEquals("foo:bar/baz", ref1.toString());
        assertEquals("foo:bar/baz".length(), ref1.length());

        var ref2 = new TagReference("foo:bar/baz");
        assertEquals("foo", ref2.namespace());
        assertEquals("bar/baz", ref2.path());
        assertEquals("foo:bar/baz", ref2.toString());
        assertEquals(ref1.length(), ref2.length());

        assertEquals(ref1, ref2);
        assertEquals(ref1.hashCode(), ref2.hashCode());
        assertNotEquals(new TagReference("foo", "bar/qux"), ref1);
    }

    @Test
    public void compareTo_orders_by_namespace_then_path() {
        var refs = Arrays.asList(
                new TagReference("a", "x"),
                new TagReference("a", "x/y.z"),
                new TagReference("f", "b"),
                new TagReference("f", "b/very.long_segment-123"),
                new TagReference("f", "b2"),
                new TagReference("long.namespace", "a"),
                new TagReference("long.namespace", "z"),
                new TagReference("z", "a"),
                new TagReference("z", "a_really/long/path.segment"),
                new TagReference("zz", "0"));
        refs.sort(TagReference::compareTo);
        assertEquals(List.of(
                "a:x",
                "a:x/y.z",
                "f:b",
                "f:b/very.long_segment-123",
                "f:b2",
                "long.namespace:a",
                "long.namespace:z",
                "z:a",
                "z:a_really/long/path.segment",
                "zz:0"), refs.stream().map(TagReference::toString).toList());
        assertTrue(new TagReference("f", "b")
                .compareTo(new TagReference("long.namespace", "b")) < 0);
        assertTrue(new TagReference("f", "b")
                .compareTo(new TagReference("f", "b/very.long_segment-123")) < 0);
    }

    @Test
    public void constructor_rejects_invalid_namespace_or_path_or_missing_colon() {
        assertThrows(IllegalArgumentException.class, () -> new TagReference("Foo", "bar"));
        assertThrows(IllegalArgumentException.class, () -> new TagReference("foo", "Bar"));
        assertThrows(IllegalArgumentException.class, () -> new TagReference("foo", ""));
        assertThrows(IllegalArgumentException.class, () -> new TagReference("", "bar"));

        assertThrows(IllegalArgumentException.class, () -> new TagReference("foo/bar/baz"));
        assertThrows(IllegalArgumentException.class, () -> new TagReference("foo:Bar"));
        assertThrows(IllegalArgumentException.class, () -> new TagReference("foo/bar:baz"));
    }

    @Test
    public void constructor_rejects_overlong_reference_strings() {
        var ns = "foo";
        var maxPathLen = 0x3FFF - ns.length() - 1;

        assertEquals(0x3FFF, (ns + ":" + "a".repeat(maxPathLen)).length());
        assertDoesNotThrow(() -> new TagReference(ns, "a".repeat(maxPathLen)));
        assertThrows(IllegalArgumentException.class, () -> new TagReference(ns, "a".repeat(maxPathLen + 1)));

        assertDoesNotThrow(() -> new TagReference(ns + ":" + "a".repeat(maxPathLen)));
        assertThrows(IllegalArgumentException.class, () -> new TagReference(ns + ":" + "a".repeat(maxPathLen + 1)));
    }
}
