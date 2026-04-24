package org.teacon.ovp.payload;

import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;
import org.teacon.ovp.util.BLS12381;
import org.teacon.ovp.util.TagReference;

import java.util.List;
import java.util.random.RandomGenerator;

import static org.junit.jupiter.api.Assertions.*;

class IdentitySignatureTest {
    private static final String CLIENT_SECRET_HEX = "15c026745a89f94dc78abebf65579b292c8c0924b2603c0736cfba6d28a47a2f";
    private static final String SERVER_SECRET_HEX = "267cc15949dcf8ef55f0a325b8f56e32d296b41251a7c94a9101b1ad41106199" +
            "3410820adc72d75744970568546b5a7a5e2305b7b48a52aff2b43f275f58c37746ad2ad93622109df93a0666cdc5dd8c899077f4" +
            "9f46f1fce99bd1520b3a41975771318129301ae63bbe78ae8628c99139b69e16153e92217ede3f00c2ec17c4";
    private static final String IDENTITY_SIGN_HEX = "03613a7807613a782f792e7a03663a6219663a622f766572792e6c6f6e675f73" +
            "65676d656e742d31323304663a6232106c6f6e672e6e616d6573706163653a61106c6f6e672e6e616d6573706163653a7a037a3a" +
            "611c7a3a615f7265616c6c792f6c6f6e672f706174682e7365676d656e74047a7a3a3000a967b927e1ef537517c9aa3664e3b31d" +
            "6a38721a9c23212615a301e3e8b43f35cdf1da7499695de8f460b4883a732f6783b4d6eb939ce3227008136c5361c1ffccad5833" +
            "f5cbd04582922eb34ce63ef4a5efa5a51e2caeb2e94a5bc2d907f374";

    @Test
    public void identitySignature_can_be_constructed_and_verified_with_voteChallenges() throws Exception {
        var clientSk = new ClientSecretKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(CLIENT_SECRET_HEX)));
        var serverSk = new ServerSecretKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_SECRET_HEX)));
        var serverPk = new ServerPublicKey(serverSk);
        var ctx = new VoteClientContext(serverPk, RandomGenerator.of("SecureRandom")).readSecretKey(clientSk);

        var commit = new ClientPointCommit(clientSk);
        var role = List.of("a:x", "a:x/y.z", "f:b", "f:b/very.long_segment-123", "f:b2",
                "long.namespace:a", "long.namespace:z", "z:a", "z:a_really/long/path.segment", "zz:0");

        var rngSource = "527b2d3a3424fef92ac5ca8b685c2bc52747e44d31042c95d215510043a929ff96832fa3cb412d1c2cd58a56882d" +
                "0d26daa887eb4f29b189d1146ed694a3cffbe89b15a0606616d3a216381230ec3add5d3633ce808776ed235aff95f7bc0aff";
        var rngBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(rngSource));
        var rng = (RandomGenerator) rngBytes::readLongLE;
        var signature = new IdentitySignature(serverSk, commit, role.stream().map(TagReference::new).toList(), rng);

        var sigOnlyDump = Unpooled.buffer(216);
        signature.dump(sigOnlyDump);
        assertEquals(IDENTITY_SIGN_HEX, ByteBufUtil.hexDump(sigOnlyDump));
        assertEquals(0, rngBytes.readableBytes());
        assertTrue(VoteChallenges.validate(ctx, signature));
    }

    @Test
    public void voteChallenges_validate_rejects_tampered_identity_signature() throws Exception {
        var clientSk = new ClientSecretKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(CLIENT_SECRET_HEX)));
        var serverSk = new ServerSecretKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_SECRET_HEX)));
        var serverPk = new ServerPublicKey(serverSk);
        var ctx = new VoteClientContext(serverPk, RandomGenerator.of("SecureRandom")).readSecretKey(clientSk);

        var encoded = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(IDENTITY_SIGN_HEX));
        var signature = new IdentitySignature(encoded);
        assertTrue(VoteChallenges.validate(ctx, signature));

        var badEncoded = Unpooled.buffer(97);
        BLS12381.stringToBytes(false, "", badEncoded);
        BLS12381.pointToSignature(signature.a, badEncoded);
        var badB = signature.a.mul(serverSk.w);
        BLS12381.pointToSignature(badB, badEncoded);
        var badSignature = new IdentitySignature(badEncoded);
        assertFalse(VoteChallenges.validate(ctx, badSignature));
    }
}
