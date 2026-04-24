package org.teacon.ovp.payload;

import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import java.util.random.RandomGenerator;

import static org.junit.jupiter.api.Assertions.*;

class CommitRevocationTest {
    private static final String CLIENT_SECRET_HEX = "15c026745a89f94dc78abebf65579b292c8c0924b2603c0736cfba6d28a47a2f";
    private static final String SERVER_PUBLIC_HEX = "954434dba2a74999c62a33faf66d79ac76c92f1a91d56a62d7a32c747741f126" +
            "15fe7782401e9c81dd5c93c4800faaa40fb6d5dfa04698ba27b83357fe61d00740d3f9394d8610c902dc461cc3eaa94fdcc7a03f" +
            "bae1d324b9ecbedb740101c995dd6d310c56b1d7ace0e66dec73dad42afba0f5c32d78c3e01da04b6d00f12877e5f58f4a5e94fc" +
            "8b4fbda7ef6a4bea111b732c73a38f3dcae2a293e5acf6af24414555196d4da1484296f001f188ddc65e88cd41bd6686923acfcc" +
            "d34a1ed582c04fc26aa35b765317e2574af340d619c531c418dba88a5dd51529ded96fc28f7cf59bd1b73d59d28ab2d822bd9114" +
            "08e6f283a32436bba95fa251afa974e7a7c387024c84627ad204b4d21bb1ed4963ec25b01c5b352c7b3a94e3a15477a0838c8145" +
            "50c8edc8089832470c978048ac29d90b4b11d4066d091853300e6029ef480c2d955f1d9ab0dc0d21aec26d6f0dc9041c99a0343f" +
            "0d09c885215d3ee366f6415468577d7d9566b6820c5eaf03091ffab838ea8906e35a6b932a8b644a";
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
    public void clientPointCommit_constructor_fromContext_matches_vector() {
        var secretBytes = ByteBufUtil.decodeHexDump(CLIENT_SECRET_HEX);
        assertEquals(32, secretBytes.length);
        var sk = assertDoesNotThrow(() -> new ClientSecretKey(Unpooled.wrappedBuffer(secretBytes)));
        var serverPk = new ServerPublicKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_PUBLIC_HEX)));
        var ctx = new VoteClientContext(serverPk, RandomGenerator.of("SecureRandom")).readSecretKey(sk);

        var expectedBytes = ByteBufUtil.decodeHexDump(CLIENT_COMMIT_HEX);
        assertEquals(48, expectedBytes.length);

        var commit = ctx.makePointCommit();
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
    public void clientRevocation_constructor_fromContext_matches_vector() {
        var secretBytes = ByteBufUtil.decodeHexDump(CLIENT_SECRET_HEX);
        assertEquals(32, secretBytes.length);
        var sk = assertDoesNotThrow(() -> new ClientSecretKey(Unpooled.wrappedBuffer(secretBytes)));
        var serverPk = new ServerPublicKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_PUBLIC_HEX)));
        var ctx = new VoteClientContext(serverPk, RandomGenerator.of("SecureRandom")).readSecretKey(sk);

        var expectedBytes = ByteBufUtil.decodeHexDump(CLIENT_REVOKE_HEX);
        assertEquals(96, expectedBytes.length);

        var cr = ctx.makeRevocation();
        var output = Unpooled.buffer(96);
        cr.dump(output);
        assertEquals(96, output.readableBytes());
        assertArrayEquals(expectedBytes, ByteBufUtil.getBytes(output));
    }
}
