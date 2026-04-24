package org.teacon.ovp.payload;

import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;
import org.teacon.ovp.util.ShortMnemonic;

import java.util.Objects;

import static org.junit.jupiter.api.Assertions.*;

class VoteClientContextTest {
    private static final String PASSWORD = "I can eat glass, it does not hurt me";
    private static final String MNEMONIC = "board flee heavy tunnel powder denial science ski answer betray cargo cat";
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
    private static final String HANDSHAKING_1_HEX = "99251e4391a23d2cd3e8cfa0ca18c63b4f3da74d71dfc73a8b74687121e4841e" +
            "9e4b8947123040954debb5f997e146968c2b35d33e3af2a791c0d4cb083ae5edd73f6d631fe13330f0e1fcf61f325709128b3331" +
            "70d64bb3c0db2f0a9653448b";
    private static final String SIGN_ENVELOPE_HEX = "c89b86f4a462ef917f4880563df33331df438f08667852a4979112a08cdc592f" +
            "2ec6c513c777253ff15b13928aa206ff99c21c0967f52b4000c4ed80f5f256c89d0d8f34e6ff11364a9db0afcddc3e6ae1ea2461" +
            "1a7579c7edade01053b0ab01afdc7ac9b4f0b3d29cd18a27571fa2a786846e4085d77f209c01dab09e7fce6737ff47f257da9c66" +
            "a4d588b43f60460fe422dadea2d6c4ee6d2e35743b50b0a76e983ce1a059b47131f3b6679a7b2db7895413d92c3658c8a96ffebf" +
            "eaed75a1975b8eb0fe21ec8fcee14bdbb66b450ed50e697cd1be528a58e8f6be16f1601d";
    private static final String SIGN_RESPONSE_HEX = "94bfedd5cc4ac2ed6bb418142179777e78b7bb452e88c569601fd08e34bd96e4" +
            "7034de5993af78ad7700648dfd2d15ac" + SIGN_ENVELOPE_HEX;
    private static final String HANDSHAKING_2_HEX = "b41932a209981359a5566c044b0989929f1924cf111d2f16ba153d9e6625bdf9" +
            "15dd2ec4e22a1096a4abc184a363aa44" + SIGN_RESPONSE_HEX;
    private static final String SIGN_OVERRIDE_HEX = "96db07bb3b9d3d965e006041125cd8a88f9b0acbee28a3e7c085b4f120e75fbe" +
            "a2087f25d90e5eff4e4d1688a261ece9" + SIGN_ENVELOPE_HEX;
    private static final String MNEM_RESPONSE_HEX = "8272798d7354c0ff29837aeaebf7c4a63345436b9996b5e6fa0c8c70ca913d68" +
            "5193755aa139c20c18fa077433431fc2" + SIGN_ENVELOPE_HEX;

    @Test
    void section1_init_and_envelope_vectors_match_dump_outputs() {
        var serverSk = new ServerSecretKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_SECRET_HEX)));
        var serverPk = new ServerPublicKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_PUBLIC_HEX)));

        var rngSource = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001" +
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "000000000000000000000000000015c026745a89f94dc78abebf65579b292c8c0924b2603c0736cfba6d28a47a2f00000000" +
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "0000000000000000000013ad0e04ee36187bda4395fadc24115b26342a0a8ddd80929a601984fb12b6aac89b86f4a462ef91" +
                "7f4880563df33331df438f08667852a4979112a08cdc592f18ab19a9f54a9274f03e5209a2ac8a9100000000000000000000" +
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "0000000000000000000000000000000000000000000000000000000000000000000000018fc317a897266c77724408d1f7f8" +
                "804d7671cbcdd4f2953af4dc4438971ac74a9ad5e5d0ec072bb0c22d42306876996140175358e7e2e5ecef3d18c2ac93c753" +
                "5b0a1325228863fe6b88afbcc2a900af2c350669fc6ee827b96b27a68b20721a";
        var rngBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(rngSource));
        var ctx = new VoteClientContext(serverPk, rngBytes::readLongLE);

        var pkDump = Unpooled.buffer(4 * 96);
        ctx.makeServerKey().dump(pkDump);
        assertEquals(SERVER_PUBLIC_HEX, ByteBufUtil.hexDump(pkDump));

        assertEquals(ctx, assertDoesNotThrow(() -> ctx.readPassword(PASSWORD.toCharArray())));
        assertFalse(ctx.holdEmptyPassword());

        var req = ctx.makePRFRequest();
        var absent = new ServerPRFAbsent(serverSk, req);
        var handshakingDump = Unpooled.buffer(48 + 48);
        req.dump(handshakingDump);
        absent.dump(handshakingDump);
        assertEquals(HANDSHAKING_1_HEX, ByteBufUtil.hexDump(handshakingDump));

        var override = assertDoesNotThrow(() -> ctx.makePRFOverride(absent, Objects::requireNonNull));
        var overrideDump = Unpooled.buffer(48 + 224);
        override.dump(overrideDump);
        assertEquals(SIGN_OVERRIDE_HEX, ByteBufUtil.hexDump(overrideDump));

        assertEquals(ctx, ctx.dropPasswordAndRotateSecretKey());
        assertTrue(ctx.holdEmptyPassword());
        assertEquals(0, rngBytes.readableBytes());
    }

    @Test
    void section1_override_requires_password_prf_even_when_secret_key_is_preloaded() {
        var serverPk = new ServerPublicKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_PUBLIC_HEX)));
        var secret = new ClientSecretKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(CLIENT_SECRET_HEX)));

        var rngSource = "95571a50b49f123ea241f5c8cc02bb31d139f9478ae7edaaaf054cca2cee0082a82d8c93f9b4f42e4366940d38fa" +
                "b890791a2c90591eb047175fa6e546417407b82c72dadd6a7d9c8e27f1ef119148d0285fc04f25f58151d08b2ca48720db8e" +
                "c5a551e0925f9f4bce2f10c31e94d33f5a5bbdac5ffb96e659cd84431d0d58f4f0109a35d8d18522b8bba7a00a516923f96b" +
                "04687323a53e546ff6ec740d52681f4e9ebbab737d7c4b5370a4103de570ac547137d820506640b71a9c01b6cd9e2d43029f" +
                "a500302e1c8a9ea20d2f9b56f00e6831e9ea08b31e7357084a25d9fb428cfc63e570a6fdb9c23a9df5ebef2f2e7b2bd10dff" +
                "f3353107686f62e0ccc12a6012e9fa5f21e2d5b6425bb7df40a67d226c44173e5b8c94f9709506aec760";
        var rngBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(rngSource));
        var ctx = new VoteClientContext(serverPk, rngBytes::readLongLE);

        assertTrue(ctx.holdEmptyPassword());
        assertEquals(ctx, ctx.readSecretKey(secret));

        var secretDump = Unpooled.buffer(32);
        ctx.makeSecretKey().dump(secretDump);
        assertEquals(CLIENT_SECRET_HEX, ByteBufUtil.hexDump(secretDump));
        assertEquals(0, rngBytes.readableBytes());
    }

    @Test
    void section2_password_login_recovers_secret_from_epsilon_by_dump_vectors() {
        var serverPk = new ServerPublicKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_PUBLIC_HEX)));

        var rngSource = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001" +
                "9a2debb3ada5a9501a106e641c063b17574d7719509a37f6daddc31d77f2992d99706be0bc7cc4366837348d9caca7a684b1" +
                "2d51f05e8f302fdb01ca1d282b569305b541c5f607a0e15200d448c02f304b7348fde4e29f62c7c1fa0d4705f74200000000" +
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "00000000000000000000079acc8ef35fa11756476054b352c1b60808c918f0ea22d6139091c633e88aa8";
        var rngBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(rngSource));
        var ctx = new VoteClientContext(serverPk, rngBytes::readLongLE);

        assertEquals(ctx, assertDoesNotThrow(() -> ctx.readPassword(PASSWORD.toCharArray())));

        var loginReq = ctx.makePRFRequest();
        var loginReqDump = Unpooled.buffer(48);
        loginReq.dump(loginReqDump);
        loginReqDump.writeBytes(ByteBufUtil.decodeHexDump(SIGN_RESPONSE_HEX));
        assertEquals(HANDSHAKING_2_HEX, ByteBufUtil.hexDump(loginReqDump));

        var present = new ServerPRFPresent(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SIGN_RESPONSE_HEX)));
        assertEquals(ctx, assertDoesNotThrow(() -> ctx.readSecretKeyByPassword(present)));

        var sk = ctx.makeSecretKey();
        var skDump = Unpooled.buffer(32);
        sk.dump(skDump);
        assertEquals(CLIENT_SECRET_HEX, ByteBufUtil.hexDump(skDump));
        assertEquals(0, rngBytes.readableBytes());
    }

    @Test
    void section2_mnemonic_recovery_recovers_secret_from_epsilon_by_readSecretKeyByMnemonic() {
        var serverPk = new ServerPublicKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_PUBLIC_HEX)));
        var present = new ServerPRFPresent(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(MNEM_RESPONSE_HEX)));
        var mnemonic = new ShortMnemonic(MNEMONIC.toCharArray());

        var rngSource = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001" +
                "29c161bb3bcf9acf7cee483d572bc3cf8849483fe26f9603641dc43cdf362a59e2093375d83e3a731e8eca01d4268cb411d5" +
                "232cb79c81ce90a277162534ae293adf56fa073dc5202e3fbaaf691b6a6dce87a5da8aa251d9ab8925ce838a8dda";
        var rngBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(rngSource));
        var ctx = new VoteClientContext(serverPk, rngBytes::readLongLE);

        assertTrue(ctx.holdEmptyPassword());
        assertEquals(ctx, assertDoesNotThrow(() -> ctx.readSecretKeyByMnemonic(present, mnemonic)));

        var sk = ctx.makeSecretKey();
        var skDump = Unpooled.buffer(32);
        sk.dump(skDump);
        assertEquals(CLIENT_SECRET_HEX, ByteBufUtil.hexDump(skDump));
        assertEquals(0, rngBytes.readableBytes());
    }
}
