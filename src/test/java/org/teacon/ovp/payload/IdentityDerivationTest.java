package org.teacon.ovp.payload;

import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import java.util.UUID;
import java.util.random.RandomGenerator;

import static org.junit.jupiter.api.Assertions.*;

class IdentityDerivationTest {
    private static final UUID WORK = UUID.fromString("89abcdef-0123-4567-89ab-cdef01234567");
    private static final String CLIENT_SECRET_HEX = "15c026745a89f94dc78abebf65579b292c8c0924b2603c0736cfba6d28a47a2f";
    private static final String SERVER_SECRET_HEX = "267cc15949dcf8ef55f0a325b8f56e32d296b41251a7c94a9101b1ad41106199" +
            "3410820adc72d75744970568546b5a7a5e2305b7b48a52aff2b43f275f58c37746ad2ad93622109df93a0666cdc5dd8c899077f4" +
            "9f46f1fce99bd1520b3a41975771318129301ae63bbe78ae8628c99139b69e16153e92217ede3f00c2ec17c4";
    private static final String EXPECTED_DUMP_HEX = "ad400d032aefad184d33f14f8debabf5bfe330cd0392f182efe74c81d1be2e65" +
            "cf5a704258f290afd6c6367b4b96f8c1";
    private static final String INDEX_BE_DUMP_HEX = "1391159f182e3de1d969a57311f2da62580373fedf1069c317c2531f9ce6aa4c" +
            "85ff0ddd752129dc90e4c77a064a69ea0cf066c33aaf07e8d83cfdbed2dd3e65b927e66feaa1aaf0ab85e36684e54c089fa39f5c" +
            "dc8f6c5f9ba2da586518df6507e88eff5fdd58e549b56651cda57729c5c86d6f6266927f5a4b69a87691d5340a38571c1204a232" +
            "df2d622599a99cc404d0073b5ddcaedb69dad08cd2e666ca1245163c28fe5ed693c90838e671c7b5eadd82b4963fe0af58e123a1" +
            "e95b43ec13cc0e1597c7c4ceb55158b123bf6e00154b02277b13e844ee2e6ad639262663f1546813c399d3e7c250f74ad8b8d0da" +
            "1321f01052ea8c2ccd501d918c5e59afb1e32dca0b0896cd203236e7370641a00e54f928634c9e0442a63218560ef52712bf8745" +
            "d128cfc3b28b8d4ae8224759a9ac05feebc5e7195743d99963acc7b6d2e32623fb6f160bedc9682cc358390b1207a184b034fb8b" +
            "1078ff47ecc39c7bceb6916662b9d06b5abadc120721bf4e676a8a50f4bdffbb73570ea1933159260b8be5a5e04e086ae2ea7871" +
            "86b9e0bf74be128d62a1ccfefab9d0fe980974e69c470c571c63d634268b413206f4e2da053fe6a6a0d444d14a09f9b8ef76e97e" +
            "f0858a2d1af9f0f686684063887d9c450805ac850e54b0cbe7c816bd504df83505898fa2bcce4cce3cee140ca5b5e28653fc5315" +
            "4c0bf61fef4c2d358f6307b16a334e0d9bc09ca64f91bd13fc76676506b6c9e4ad7d07a80c20d8539b005cbbfe47ac5d23513b92" +
            "24f3607e0b182bdbfc412c2a6d96fecfff28085fd76fae8f";

    @Test
    public void identityDerivation_dump_and_index_match_vectors_and_roundTrip_from_dump_bytes() {
        var clientSkBytes = ByteBufUtil.decodeHexDump(CLIENT_SECRET_HEX);
        var clientSk = assertDoesNotThrow(() -> new ClientSecretKey(Unpooled.wrappedBuffer(clientSkBytes)));
        var serverSk = new ServerSecretKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_SECRET_HEX)));
        var serverPk = new ServerPublicKey(serverSk);
        var ctx = new VoteClientContext(serverPk, RandomGenerator.of("SecureRandom")).readSecretKey(clientSk);

        var derived1 = ctx.makeIdentityDerivation(WORK);

        var dump1 = Unpooled.buffer(48);
        derived1.dump(dump1);
        assertEquals(48, dump1.readableBytes());
        assertEquals(EXPECTED_DUMP_HEX, ByteBufUtil.hexDump(dump1));

        var index1 = derived1.index();
        assertEquals(576, index1.asBytes().length);
        assertEquals(INDEX_BE_DUMP_HEX, index1.toString());

        var dumpBytes = ByteBufUtil.decodeHexDump(EXPECTED_DUMP_HEX);
        var in = Unpooled.wrappedBuffer(dumpBytes);
        var derived2 = assertDoesNotThrow(() -> new IdentityDerivation(in));
        assertEquals(0, in.readableBytes());

        var dump2 = Unpooled.buffer(48);
        derived2.dump(dump2);
        assertEquals(EXPECTED_DUMP_HEX, ByteBufUtil.hexDump(dump2));
        assertEquals(INDEX_BE_DUMP_HEX, derived2.index().toString());
    }

    @Test
    public void identityDerivation_constructor_rejects_invalid_signature_bytes() {
        var bad = Unpooled.buffer(48).writeZero(48);
        assertThrows(IllegalArgumentException.class, () -> new IdentityDerivation(bad));
    }
}
