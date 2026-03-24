package org.teacon.ovp.payload;

import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public final class CommitRevocationTest {
    private static final String CLIENT_SECRET_HEX = "15c026745a89f94dc78abebf65579b292c8c0924b2603c0736cfba6d28a47a2f";
    private static final String CLIENT_REVOKE_HEX = "8374fd218fdebcf24ee4a15b77ab03d5c98f68a16a7e7af11435ccd79ac60b22" +
            "8a5d84e53b56f88fc6969bfb55e0ecc20fcadcf2b740dd07adf87beec5cf3b34c1b7a2080dd1c122e5368f0bb5b149444a1a3231" +
            "7c39e07d71084b101964c8bc";
    private static final String CLIENT_COMMIT_HEX = "96db07bb3b9d3d965e006041125cd8a88f9b0acbee28a3e7c085b4f120e75fbe" +
            "a2087f25d90e5eff4e4d1688a261ece9";

    @Test
    public void clientPointCommit_dump_roundTrips_inputBytes() {
        var inputBytes = ByteBufUtil.decodeHexDump(CLIENT_COMMIT_HEX);
        assertEquals(48, inputBytes.length);

        var input = Unpooled.wrappedBuffer(inputBytes);
        var commit = assertDoesNotThrow(() -> new ClientPointCommit(input));

        var output = Unpooled.buffer(48);
        commit.dump(output);
        assertEquals(48, output.readableBytes());
        assertArrayEquals(inputBytes, ByteBufUtil.getBytes(output));
    }

    @Test
    public void clientPointCommit_constructor_fromSecretKey_matches_vector() {
        var secretBytes = ByteBufUtil.decodeHexDump(CLIENT_SECRET_HEX);
        assertEquals(32, secretBytes.length);
        var sk = assertDoesNotThrow(() -> new ClientSecretKey(Unpooled.wrappedBuffer(secretBytes)));

        var expectedBytes = ByteBufUtil.decodeHexDump(CLIENT_COMMIT_HEX);
        assertEquals(48, expectedBytes.length);

        var commit = new ClientPointCommit(sk);
        var output = Unpooled.buffer(48);
        commit.dump(output);
        assertEquals(48, output.readableBytes());
        assertArrayEquals(expectedBytes, ByteBufUtil.getBytes(output));
    }

    @Test
    public void clientRevocation_dump_roundTrips_inputBytes() {
        var inputBytes = ByteBufUtil.decodeHexDump(CLIENT_REVOKE_HEX);
        assertEquals(96, inputBytes.length);

        var input = Unpooled.wrappedBuffer(inputBytes);
        var cr = assertDoesNotThrow(() -> new ClientRevocation(input));

        var output = Unpooled.buffer(96);
        cr.dump(output);
        assertEquals(96, output.readableBytes());
        assertArrayEquals(inputBytes, ByteBufUtil.getBytes(output));
    }

    @Test
    public void clientRevocation_constructor_fromSecretKey_matches_vector() {
        var secretBytes = ByteBufUtil.decodeHexDump(CLIENT_SECRET_HEX);
        assertEquals(32, secretBytes.length);
        var sk = assertDoesNotThrow(() -> new ClientSecretKey(Unpooled.wrappedBuffer(secretBytes)));

        var expectedBytes = ByteBufUtil.decodeHexDump(CLIENT_REVOKE_HEX);
        assertEquals(96, expectedBytes.length);

        var cr = new ClientRevocation(sk);
        var output = Unpooled.buffer(96);
        cr.dump(output);
        assertEquals(96, output.readableBytes());
        assertArrayEquals(expectedBytes, ByteBufUtil.getBytes(output));
    }
}
