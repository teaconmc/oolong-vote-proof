package org.teacon.ovp.payload;

import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;
import org.teacon.ovp.util.BLS12381;
import org.teacon.ovp.util.GCM256Cipher;
import org.teacon.ovp.util.ShortMnemonic;

import java.util.random.RandomGenerator;

import static org.junit.jupiter.api.Assertions.*;

class PRFHandshakingTest {
    private static final String SERVER_SECRET_HEX = "267cc15949dcf8ef55f0a325b8f56e32d296b41251a7c94a9101b1ad41106199" +
            "3410820adc72d75744970568546b5a7a5e2305b7b48a52aff2b43f275f58c37746ad2ad93622109df93a0666cdc5dd8c899077f4" +
            "9f46f1fce99bd1520b3a41975771318129301ae63bbe78ae8628c99139b69e16153e92217ede3f00c2ec17c4";

    private static final char[] PASS = "0137fvqgxuocpetm8hzywsk49j25bnal6dri".toCharArray();

    @Test
    public void prf_payloads_dump_roundTrip_for_session_request_and_absent_answer() {
        var random = RandomGenerator.of("SecureRandom");
        var serverSkBytes = ByteBufUtil.decodeHexDump(SERVER_SECRET_HEX);
        var serverSk = assertDoesNotThrow(() -> new ServerSecretKey(Unpooled.wrappedBuffer(serverSkBytes)));
        var serverPk = assertDoesNotThrow(() -> new ServerPublicKey(serverSk));

        var session1 = new ClientPRFSession(PASS, random);
        assertTrue(session1.secret().isEmpty());
        var sessionDump1 = Unpooled.buffer(112);
        session1.dump(sessionDump1);
        assertEquals(112, sessionDump1.readableBytes());

        var session2Buf = sessionDump1.copy();
        var session2 = assertDoesNotThrow(() -> new ClientPRFSession(session2Buf));
        assertEquals(0, session2Buf.readableBytes());
        assertTrue(session2.secret().isEmpty());
        var sessionDump2 = Unpooled.buffer(112);
        session2.dump(sessionDump2);
        assertArrayEquals(ByteBufUtil.getBytes(sessionDump1), ByteBufUtil.getBytes(sessionDump2));

        var req1 = new ClientPRFRequest(session1);
        var reqDump1 = Unpooled.buffer(48);
        req1.dump(reqDump1);
        assertEquals(48, reqDump1.readableBytes());
        var req2Buf = reqDump1.copy();
        var req2 = assertDoesNotThrow(() -> new ClientPRFRequest(req2Buf));
        assertEquals(0, req2Buf.readableBytes());
        var reqDump2 = Unpooled.buffer(48);
        req2.dump(reqDump2);
        assertArrayEquals(ByteBufUtil.getBytes(reqDump1), ByteBufUtil.getBytes(reqDump2));

        var ans1 = new ServerPRFAbsent(serverSk, req1);
        var ansDump1 = Unpooled.buffer(48);
        ans1.dump(ansDump1);
        assertEquals(48, ansDump1.readableBytes());
        var ans2Buf = ansDump1.copy();
        var ans2 = assertDoesNotThrow(() -> new ServerPRFAbsent(ans2Buf));
        assertEquals(0, ans2Buf.readableBytes());
        var ansDump2 = Unpooled.buffer(48);
        ans2.dump(ansDump2);
        assertArrayEquals(ByteBufUtil.getBytes(ansDump1), ByteBufUtil.getBytes(ansDump2));
        assertTrue(VoteChallenges.validate(serverPk, req1, ans1));

        var badN = req1.m.mul(serverSk.w);
        var badAnsDump = Unpooled.buffer(48);
        BLS12381.pointToSignature(badN, badAnsDump);
        var badAns = new ServerPRFAbsent(badAnsDump.copy());
        assertFalse(VoteChallenges.validate(serverPk, req1, badAns));
    }

    @Test
    public void prf_present_answer_dump_roundTrip_and_session_can_derive_secret_via_pass_or_recoveryKey() {
        var random = RandomGenerator.of("SecureRandom");
        var serverSkBytes = ByteBufUtil.decodeHexDump(SERVER_SECRET_HEX);
        var serverSk = assertDoesNotThrow(() -> new ServerSecretKey(Unpooled.wrappedBuffer(serverSkBytes)));

        var session0 = new ClientPRFSession(PASS, random);
        var request = new ClientPRFRequest(session0);

        // A fixed, valid non-zero secret key encoding (1) as the encrypted master secret.
        var master = new byte[32];
        master[31] = 0x01;

        var n = request.m.mul(serverSk.v);
        var passKeyBuf = Unpooled.buffer(32);
        var passKeyField = BLS12381.hashToScalar(PASS, n.mul(BLS12381.fieldInverse(session0.r)));
        BLS12381.fieldToBytes(passKeyField, passKeyBuf);
        var passKey = ByteBufUtil.getBytes(passKeyBuf);

        var ePass = new GCM256Cipher(random, master, passKey);
        var eMnem = new GCM256Cipher(random, master, passKey);
        var present1 = new ServerPRFPresent(serverSk, request, ePass, eMnem);

        var presentDump1 = Unpooled.buffer(168);
        present1.dump(presentDump1);
        assertEquals(168, presentDump1.readableBytes());
        var present2Buf = presentDump1.copy();
        var present2 = assertDoesNotThrow(() -> new ServerPRFPresent(present2Buf));
        assertEquals(0, present2Buf.readableBytes());
        var presentDump2 = Unpooled.buffer(168);
        present2.dump(presentDump2);
        assertArrayEquals(ByteBufUtil.getBytes(presentDump1), ByteBufUtil.getBytes(presentDump2));

        var sessionPass = assertDoesNotThrow(() -> new ClientPRFSession(session0, present1, PASS));
        assertTrue(sessionPass.secret().isPresent());

        var recoveryKey = new ShortMnemonic(random);
        var mnemKeyBuf = Unpooled.buffer(32);
        BLS12381.pbkdf2(recoveryKey.chars(), "mnemonic", mnemKeyBuf, 32);
        var mnemKey = ByteBufUtil.getBytes(mnemKeyBuf);

        var ePass2 = new GCM256Cipher(random, master, mnemKey);
        var eMnem2 = new GCM256Cipher(random, master, mnemKey);
        var presentMnem = new ServerPRFPresent(serverSk, request, ePass2, eMnem2);

        var sessionMnem = assertDoesNotThrow(() -> new ClientPRFSession(session0, presentMnem, recoveryKey));
        assertTrue(sessionMnem.secret().isPresent());
    }

    @Test
    public void client_prf_override_dump_roundTrips_and_pass_mnem_decrypt_to_same_masterSecret() {
        var random = RandomGenerator.of("SecureRandom");

        var serverSkBytes = ByteBufUtil.decodeHexDump(SERVER_SECRET_HEX);
        var serverSk = assertDoesNotThrow(() -> new ServerSecretKey(Unpooled.wrappedBuffer(serverSkBytes)));

        var session = new ClientPRFSession(PASS, random);
        var request = new ClientPRFRequest(session);
        var answer = new ServerPRFAbsent(serverSk, request);
        var recoveryKey = new ShortMnemonic(random);

        var override = new ClientPRFOverride(session, answer, PASS, recoveryKey, random);
        var prfResult = answer.n.mul(BLS12381.fieldInverse(session.r));
        var passKeyBuf = Unpooled.buffer(32);
        BLS12381.fieldToBytes(BLS12381.hashToScalar(PASS, prfResult), passKeyBuf);
        var passKey = ByteBufUtil.getBytes(passKeyBuf);

        var mnemKeyBuf = Unpooled.buffer(32);
        BLS12381.pbkdf2(recoveryKey.chars(), "mnemonic", mnemKeyBuf, 32);
        var mnemKey = ByteBufUtil.getBytes(mnemKeyBuf);

        assertEquals(60, override.pass().raw().length);
        assertEquals(60, override.mnem().raw().length);

        var masterFromPass = override.pass().decrypt(passKey);
        var masterFromMnem = override.mnem().decrypt(mnemKey);
        assertEquals(32, masterFromPass.length);
        assertArrayEquals(masterFromPass, masterFromMnem);

        var dump1 = Unpooled.buffer(120);
        override.dump(dump1);
        assertEquals(120, dump1.readableBytes());

        var parsedBuf = dump1.copy();
        var parsed = new ClientPRFOverride(parsedBuf);
        assertEquals(0, parsedBuf.readableBytes());

        var dump2 = Unpooled.buffer(120);
        parsed.dump(dump2);
        assertArrayEquals(ByteBufUtil.getBytes(dump1), ByteBufUtil.getBytes(dump2));
    }
}
