package org.teacon.ovp.util;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class WorkInformationTest {
    @Test
    public void constructors_and_accessors_work_for_common_values() {
        var uuid = new UUID(1L, 2L);
        var withoutAlias = new WorkInformation(uuid, "hello");
        assertEquals(uuid, withoutAlias.uuid());
        assertEquals("hello", withoutAlias.desc());
        assertTrue(withoutAlias.alias().isEmpty());

        var withAlias = new WorkInformation(uuid, "world", "#namespace");
        assertEquals(uuid, withAlias.uuid());
        assertEquals("world", withAlias.desc());
        assertEquals("#namespace", withAlias.alias().orElseThrow());
    }

    @Test
    public void constructor_rejects_invalid_description_or_alias() {
        var uuid = new UUID(1L, 2L);
        var ex1 = assertThrows(IllegalArgumentException.class, () -> new WorkInformation(uuid, ""));
        assertTrue(ex1.getMessage().contains("empty desc"));

        var tooLong = "a".repeat(0x200000);
        var ex2 = assertThrows(IllegalArgumentException.class, () -> new WorkInformation(uuid, tooLong));
        assertTrue(ex2.getMessage().contains("too many bytes of desc"));

        var ex3 = assertThrows(IllegalArgumentException.class, () -> new WorkInformation(uuid, "hello", ""));
        assertTrue(ex3.getMessage().contains("empty alias"));

        var ex4 = assertThrows(IllegalArgumentException.class, () -> new WorkInformation(uuid, "hello", "namespace"));
        assertTrue(ex4.getMessage().contains("invalid alias"));

        var ex5 = assertThrows(IllegalArgumentException.class, () -> new WorkInformation(uuid, "hello", "#NameSpace"));
        assertTrue(ex5.getMessage().contains("invalid alias"));
    }
}
