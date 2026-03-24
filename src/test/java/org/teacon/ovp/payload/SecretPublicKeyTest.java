package org.teacon.ovp.payload;

import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public final class SecretPublicKeyTest {
    private static final String CLIENT_SECRET_HEX = "15c026745a89f94dc78abebf65579b292c8c0924b2603c0736cfba6d28a47a2f";
    private static final String SERVER_SECRET_HEX = "267cc15949dcf8ef55f0a325b8f56e32d296b41251a7c94a9101b1ad41106199" +
            "3410820adc72d75744970568546b5a7a5e2305b7b48a52aff2b43f275f58c37746ad2ad93622109df93a0666cdc5dd8c899077f4" +
            "9f46f1fce99bd1520b3a41975771318129301ae63bbe78ae8628c99139b69e16153e92217ede3f00c2ec17c4";
    private static final String SERVER_PUBLIC_HEX = "954434dba2a74999c62a33faf66d79ac76c92f1a91d56a62d7a32c747741f126" +
            "15fe7782401e9c81dd5c93c4800faaa40fb6d5dfa04698ba27b83357fe61d00740d3f9394d8610c902dc461cc3eaa94fdcc7a03f" +
            "bae1d324b9ecbedb740101c995dd6d310c56b1d7ace0e66dec73dad42afba0f5c32d78c3e01da04b6d00f12877e5f58f4a5e94fc" +
            "8b4fbda7ef6a4bea111b732c73a38f3dcae2a293e5acf6af24414555196d4da1484296f001f188ddc65e88cd41bd6686923acfcc" +
            "d34a1ed582c04fc26aa35b765317e2574af340d619c531c418dba88a5dd51529ded96fc28f7cf59bd1b73d59d28ab2d822bd9114" +
            "08e6f283a32436bba95fa251afa974e7a7c387024c84627ad204b4d21bb1ed4963ec25b01c5b352c7b3a94e3a15477a0838c8145" +
            "50c8edc8089832470c978048ac29d90b4b11d4066d091853300e6029ef480c2d955f1d9ab0dc0d21aec26d6f0dc9041c99a0343f" +
            "0d09c885215d3ee366f6415468577d7d9566b6820c5eaf03091ffab838ea8906e35a6b932a8b644a";

    @Test
    public void clientSecretKey_dump_roundTrips_inputBytes() {
        var inputBytes = ByteBufUtil.decodeHexDump(CLIENT_SECRET_HEX);
        assertEquals(32, inputBytes.length);

        var input = Unpooled.wrappedBuffer(inputBytes);
        var sk = assertDoesNotThrow(() -> new ClientSecretKey(input));

        var output = Unpooled.buffer(32);
        sk.dump(output);
        assertEquals(32, output.readableBytes());
        assertArrayEquals(inputBytes, ByteBufUtil.getBytes(output));
    }

    @Test
    public void clientSecretKey_constructor_rejects_allZero_bytes() {
        var input = Unpooled.buffer(32).writeZero(32);
        assertThrows(IllegalArgumentException.class, () -> new ClientSecretKey(input));
    }

    @Test
    public void serverSecretKey_dump_roundTrips_inputBytes() {
        var inputBytes = ByteBufUtil.decodeHexDump(SERVER_SECRET_HEX);
        assertEquals(128, inputBytes.length);

        var input = Unpooled.wrappedBuffer(inputBytes);
        var sk = assertDoesNotThrow(() -> new ServerSecretKey(input));

        var output = Unpooled.buffer(128);
        sk.dump(output);
        assertEquals(128, output.readableBytes());
        assertArrayEquals(inputBytes, ByteBufUtil.getBytes(output));
    }

    @Test
    public void serverSecretKey_constructor_rejects_truncated_bytes() {
        var goodBytes = ByteBufUtil.decodeHexDump(SERVER_SECRET_HEX);
        assertEquals(128, goodBytes.length);
        var input = Unpooled.wrappedBuffer(Arrays.copyOf(goodBytes, 127));
        assertThrows(IndexOutOfBoundsException.class, () -> new ServerSecretKey(input));
    }

    @Test
    public void serverPublicKey_dump_roundTrips_vector_and_matches_derived_publicKey() {
        var serverSkBytes = ByteBufUtil.decodeHexDump(SERVER_SECRET_HEX);
        var sk = assertDoesNotThrow(() -> new ServerSecretKey(Unpooled.wrappedBuffer(serverSkBytes)));

        var expected = Unpooled.buffer(4 * 96);
        var pk1 = new ServerPublicKey(sk);
        pk1.dump(expected);

        var inputBytes = ByteBufUtil.decodeHexDump(SERVER_PUBLIC_HEX);
        assertEquals(4 * 96, inputBytes.length);
        var pk2 = assertDoesNotThrow(() -> new ServerPublicKey(Unpooled.wrappedBuffer(inputBytes)));

        var output = Unpooled.buffer(4 * 96);
        pk2.dump(output);
        assertEquals(4 * 96, output.readableBytes());
        assertEquals(4 * 96, expected.readableBytes());
        assertArrayEquals(ByteBufUtil.getBytes(expected), ByteBufUtil.getBytes(output));
    }

    @Test
    public void serverPublicKey_constructor_accepts_vector_bytes_and_dump_matches_input() {
        var inputBytes = ByteBufUtil.decodeHexDump(SERVER_PUBLIC_HEX);
        assertEquals(4 * 96, inputBytes.length);

        var input = Unpooled.wrappedBuffer(inputBytes);
        var pk = assertDoesNotThrow(() -> new ServerPublicKey(input));

        var output = Unpooled.buffer(4 * 96);
        pk.dump(output);
        assertEquals(4 * 96, output.readableBytes());
        assertArrayEquals(inputBytes, ByteBufUtil.getBytes(output));
    }
}
