package org.teacon.ovp.payload;

import com.google.common.hash.HashCode;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;
import org.teacon.ovp.storage.DBService;
import org.teacon.ovp.util.TagReference;
import org.teacon.ovp.util.VoteInformation;
import org.teacon.ovp.util.WorkInformation;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import static org.junit.jupiter.api.Assertions.*;

class VoteServerContextTest {
    private static final String SEED = "The quick brown fox jumps over the lazy dog";
    private static final UUID USER_UUID = UUID.fromString("2cb555d0-6aa0-42eb-8b6d-ebb67f89e476");
    private static final UUID FAKE_UUID = UUID.fromString("440b3fc1-d669-4045-b340-d74d6ca07b47");
    private static final UUID WORK_UUID = UUID.fromString("601dab27-07cf-4e73-91fe-62f0e147948e");
    private static final String VOTE_INFO_TEXT = "vote=yes;comment=protocol-demo";
    private static final VoteInformation VOTE_INFO = new VoteInformation(Map.of(
            new TagReference("a", "z"), VoteInformation.Level.TWO,
            new TagReference("a", "a"), VoteInformation.Level.THREE_HALF,
            new TagReference("b", "x"), VoteInformation.Level.ONE), List.of("first", "second"));
    private static final Set<TagReference> ROLES = Set.of(
            new TagReference("a:x"), new TagReference("a:x/y.z"),
            new TagReference("f:b"), new TagReference("f:b/very.long_segment-123"),
            new TagReference("f:b2"), new TagReference("long.namespace:a"),
            new TagReference("long.namespace:z"), new TagReference("z:a"),
            new TagReference("z:a_really/long/path.segment"), new TagReference("zz:0"));
    private static final String SERVER_SECRET_HEX = "3a01cbcae1502275499c5216fe0ef346a3a8d79b09eb256a72c06006f20f5463" +
            "0fa5ea7e944093acf540111fe6bc0075db52d6ffc4f3f48b78edc9f4281e6ea457a4e491ab42232e5ab70683630055a47c998aba" +
            "ba342a35a99d0e89b851dee01a550bdf8a1d8a10737670c83adc8c83aa331f76cfc0900a2578024a7af6a44d";
    private static final String SERVER_PUBLIC_HEX = "8ac0af1891c0e926a62297354bbdefdc4be8939a46408fd3fbecda696ba45c61" +
            "febebcd4ef93d756151b9614e686da6e0c84c1fcee4e46a2ca007cb2175235069811c5e41626a6d233da9d4d9ff6a7a71c1170dc" +
            "7806cc19e4d84095fcbf1427a60817a632455b959e53c5e9d8282c37a48ccbfef6460aec5fa3385f49c98744a2f1713897bf90bf" +
            "d460e1d769b7c39b04e9a6d16d1c48fff3bcc084bfe9f8956b4ed07073b5c7d285b71f32defc2efc6a96d2c674420e9d87c53078" +
            "a72490d3afededa3113de85171f871e144ca53fd30a9f1d8d9809cea0d23f9546cac2185b55c6ef49898fedc4aaf94288d1ef5f3" +
            "00e7cfe505e0976878bed7d0f9dd98cf6075f0cf24da05f33023622abb1faadb88ad49ff9ba2df1f370ed97159e49d52ad478aab" +
            "268ae379903accf4c4d668a90351eddda400a1a150f935b2a74283fe7212e4f6c87cd0557e7c00a3060b5785151d863b585ae853" +
            "b027a454295bf9657ad9c07d6781dc9503331b06fe5450181f08d831e7128e4806b0204acb97ffde";
    private static final String SERVER_ABSENT_HEX = "add6ff30bd428078938854a51b9926756acec10d514a0eb3ede11359341e93fb" +
            "346b4385c152274fd7613ee45536703002ebaedc3543053b64f63f5154a702298b7af86dc0475e311ab348950fab873f7c65c34b" +
            "8b73c218a06484390867cf3ea60817a632455b959e53c5e9d8282c37a48ccbfef6460aec5fa3385f49c98744a2f1713897bf90bf" +
            "d460e1d769b7c39b04e9a6d16d1c48fff3bcc084bfe9f8956b4ed07073b5c7d285b71f32defc2efc6a96d2c674420e9d87c53078" +
            "a72490d3afededa3113de85171f871e144ca53fd30a9f1d8d9809cea0d23f9546cac2185b55c6ef49898fedc4aaf94288d1ef5f3" +
            "00e7cfe505e0976878bed7d0f9dd98cf6075f0cf24da05f33023622abb1faadb88ad49ff9ba2df1f370ed97159e49d52ad478aab" +
            "268ae379903accf4c4d668a90351eddda400a1a150f935b2a74283fe7212e4f6c87cd0557e7c00a3060b5785151d863b585ae853" +
            "b027a454295bf9657ad9c07d6781dc9503331b06fe5450181f08d831e7128e4806b0204acb97ffde";
    private static final String CLIENT_COMMIT_HEX = "856adae158d777e0787d0d5d61b259a75aefff532ed7a6a5d19285884ad8707f" +
            "3e8945e17a41db019e15b40fdf595e8c";
    private static final String CLIENT_SIGN_1_HEX = "b8f837951d905ec56029daaba0fc1aec87c9d516a977b6b6e763406773e9ba69" +
            "79512ed365d47c8cdda77e8978171076";
    private static final String PRF_RESULTS_1_HEX = "954f4db847511394feed1f1488471c243eb2de54810060f1b50bb3d96d6708b8" +
            "adab6615bf0beb6c596a38eb25068613";
    private static final String PRF_OVERRIDES_HEX = "856adae158d777e0787d0d5d61b259a75aefff532ed7a6a5d19285884ad8707f" +
            "3e8945e17a41db019e15b40fdf595e8cdbc7c29d3a512abc748bb283bf363e6a7e0fc039f847674f8a0e32e85cb71308b3eeed2d" +
            "a7f6e5089c4e8ef9cc9aad2d71005c1bcb7c42185945395f47db7827d1e80522f716eb0c711aeba4e17277806c0909ca904cfe72" +
            "40579bbbf0cea6968231960d9e6e816c2102f305858ee49eaa97a40587b2801f7b5191fc6e600848050920cc4e9cb3e20481be29" +
            "0d3e7c61bfe2a347d015575f65b504a45fd80ef0a38f55bc19565929c6adde5540d9ff0ff3fa1e10633162d773de2aa618fae33e" +
            "b17f0e1058d594925ec1d8a2f97ed7121396fc0bf56c869b813df1faf0a7363d";
    private static final String SERVER_LOOKUP_HEX = "2cb555d06aa042eb8b6debb67f89e476856adae158d777e0787d0d5d61b259a7" +
            "5aefff532ed7a6a5d19285884ad8707f3e8945e17a41db019e15b40fdf595e8cdbc7c29d3a512abc748bb283bf363e6a7e0fc039" +
            "f847674f8a0e32e85cb71308b3eeed2da7f6e5089c4e8ef9cc9aad2d71005c1bcb7c42185945395f47db7827d1e80522f716eb0c" +
            "711aeba4e17277806c0909ca904cfe7240579bbbf0cea6968231960d9e6e816c2102f305858ee49eaa97a40587b2801f7b5191fc" +
            "6e600848050920cc4e9cb3e20481be290d3e7c61bfe2a347d015575f65b504a45fd80ef0a38f55bc19565929c6adde5540d9ff0f" +
            "f3fa1e10633162d773de2aa618fae33eb17f0e1058d594925ec1d8a2f97ed7121396fc0bf56c869b813df1faf0a7363d03613a78" +
            "07613a782f792e7a03663a6219663a622f766572792e6c6f6e675f7365676d656e742d31323304663a6232106c6f6e672e6e616d" +
            "6573706163653a61106c6f6e672e6e616d6573706163653a7a037a3a611c7a3a615f7265616c6c792f6c6f6e672f706174682e73" +
            "65676d656e74047a7a3a3000";
    private static final String CLIENT_SIGN_2_HEX = "93fff4a40c30712bcef5490c324e5cb0a15352c81873f0f47987a59e8eb32f62" +
            "2c37082c3d49a82f93bcc6c193c57f62";
    private static final String PRF_RESULTS_2_HEX = "a6aa7883fa7c7c516e9582503d688cf9b3d70069da12590218bdff6c18d0dfdb" +
            "83ac172355d82aa25f3074eef9107ceadbc7c29d3a512abc748bb283bf363e6a7e0fc039f847674f8a0e32e85cb71308" +
            "b3eeed2da7f6e5089c4e8ef9cc9aad2d71005c1bcb7c42185945395f47db7827d1e80522f716eb0c711aeba4e17277806c0909ca" +
            "904cfe7240579bbbf0cea6968231960d9e6e816c2102f305858ee49eaa97a40587b2801f7b5191fc6e600848050920cc4e9cb3e2" +
            "0481be290d3e7c61bfe2a347d015575f65b504a45fd80ef0a38f55bc19565929c6adde5540d9ff0ff3fa1e10633162d773de2aa6" +
            "18fae33eb17f0e1058d594925ec1d8a2f97ed7121396fc0bf56c869b813df1faf0a7363d";
    private static final String CLIENT_SIGN_3_HEX = "a5d6ff0aa2245acca9c018723a90f62d78adba6c6466d5c835c21330514f34ca" +
            "9500b215d57f6aa9495eff9d9edf7f3d";
    private static final String PRF_RESULTS_3_HEX = "a7c1e9c114f1a560bab707296878a460506c77b9113922bca953990ec6558219" +
            "83e8a02f154f6b002340bc075f61bf6f";
    private static final String SIGN_RESPONSE_HEX = "03613a7807613a782f792e7a03663a6219663a622f766572792e6c6f6e675f73" +
            "65676d656e742d31323304663a6232106c6f6e672e6e616d6573706163653a61106c6f6e672e6e616d6573706163653a7a037a3a" +
            "611c7a3a615f7265616c6c792f6c6f6e672f706174682e7365676d656e74047a7a3a3000a33cd197e0bb215e0e1b46d4967329a0" +
            "1cfaf5353968e5bf43702a74ed14c081115effc3133b98fcd65f7b94ccc7ecbb96e915629f89127452bb4b523e6b588f0fba10a8" +
            "88481c1635193c955890392f425bb419cf4be2016813336633758b2f";
    private static final String BLINDED_PROOF_HEX = "601dab2707cf4e7391fe62f0e147948e9717324f9c5a011110bbcbca8bea4b2d" +
            "f4caa2fc7f69a1b6da490c1750594481dee2fe1dc0c9a7310c5165c7531de184430003613a61400003613a7a3c0003623a78fffe" +
            "056669727374067365636f6e6403613a7807613a782f792e7a03663a6219663a622f766572792e6c6f6e675f7365676d656e742d" +
            "31323304663a6232106c6f6e672e6e616d6573706163653a61106c6f6e672e6e616d6573706163653a7a037a3a610098ea2bd972" +
            "0bf56a962f72e92e66de6f6590c151df1d7b43a383b8adc2a86d446fc7fc662592388b19e8a6e9b26e2ff3ab4c81b133e7a97a86" +
            "4097e9901efe74ae011ab0ea116d8c427af52d91b17200618486a063f525dce943e17556e1e7c213cd9e244269940c92316eb527" +
            "845ff6b1b289a539086cbfa32192d01c7a976f3d273b35395be42b4e955f7cd52777a30959a264404748d98c3e576e18e7da72";
    private static final String CLIENT_REVOKE_HEX = "8c5313e939614fa5187905bd2ca3d3f67f5e4704d77983af07f692ca21ebe333" +
            "a4cc605b46b69b256300b3883f8e007e0557aacd48fa006a8915cb83c302a39c584306440fdb0d5112f4ac8e0647f0faf88c4df6" +
            "65e1d6ab69c87b1857d5e56a";

    @Test
    void section1_server_setup_derives_expected_secret_and_public_keys() {
        var db = new MemoryDB();
        var rngBytes = Unpooled.EMPTY_BUFFER;
        var server = new VoteServerContext(SEED.toCharArray(), db, rngBytes::readLongLE);

        var userSecret = server.makeSecretKey(USER_UUID);
        var userSecretDump = Unpooled.buffer(128);
        userSecret.dump(userSecretDump);
        assertEquals(SERVER_SECRET_HEX, ByteBufUtil.hexDump(userSecretDump));

        var userPublic = server.makePublicKey(USER_UUID);
        var userPublicDump = Unpooled.buffer(384);
        userPublic.dump(userPublicDump);
        assertEquals(SERVER_PUBLIC_HEX, ByteBufUtil.hexDump(userPublicDump));

        var absentPublic = server.makePublicKey(FAKE_UUID);
        var absentPublicDump = Unpooled.buffer(384);
        absentPublic.dump(absentPublicDump);
        assertEquals(SERVER_ABSENT_HEX, ByteBufUtil.hexDump(absentPublicDump));
        assertEquals(0, rngBytes.readableBytes());
    }

    @Test
    void section2_registration_request_and_override_produce_storable_account_entry() {
        var db = new MemoryDB();
        var rngBytes = Unpooled.EMPTY_BUFFER;
        var server = new VoteServerContext(SEED.toCharArray(), db, rngBytes::readLongLE);
        var requestBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(CLIENT_SIGN_1_HEX));
        var request = assertDoesNotThrow(() -> ClientPRFRequest.load(requestBytes));
        var answer = server.makePRFAbsent(USER_UUID, request);
        var answerDump = Unpooled.buffer();
        answer.dump(answerDump);
        assertEquals(PRF_RESULTS_1_HEX, ByteBufUtil.hexDump(answerDump));

        var overrideBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(PRF_OVERRIDES_HEX));
        var override = assertDoesNotThrow(() -> ClientPRFOverride.load(overrideBytes));
        var entry = new IdentityUserEntry(USER_UUID, override, ROLES);
        db.accounts.put(entry.uuid(), entry);

        assertEquals(USER_UUID, entry.uuid());
        assertEquals(ROLES, entry.roles());
        var entryDump = Unpooled.buffer();
        entry.dump(entryDump);
        assertEquals(SERVER_LOOKUP_HEX, ByteBufUtil.hexDump(entryDump));

        var dumped = Unpooled.buffer();
        entry.dump(dumped);
        var loaded = assertDoesNotThrow(() -> IdentityUserEntry.load(dumped.readerIndex(0)));
        assertEquals(entry.uuid(), loaded.uuid());
        assertEquals(entry.envelope(), loaded.envelope());
        assertEquals(entry.roles(), loaded.roles());
        assertEquals(0, rngBytes.readableBytes());
    }

    @Test
    void section3_login_and_recovery_makePrfPresent_supports_real_account_and_fake_account() {
        var db = new MemoryDB();
        var rngBytes = Unpooled.EMPTY_BUFFER;
        var server = new VoteServerContext(SEED.toCharArray(), db, rngBytes::readLongLE);
        var entryBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_LOOKUP_HEX));
        var entry = assertDoesNotThrow(() -> IdentityUserEntry.load(entryBytes));
        db.accounts.put(USER_UUID, entry);
        db.works.add(new WorkInformation(WORK_UUID, VOTE_INFO_TEXT, "#demo"));

        var loginRequestBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(CLIENT_SIGN_2_HEX));
        var loginRequest = assertDoesNotThrow(() -> ClientPRFRequest.load(loginRequestBytes));
        var loginPresent = server.makePRFPresent(USER_UUID, loginRequest).toCompletableFuture().join();
        var loginPresentDump = Unpooled.buffer();
        loginPresent.dump(loginPresentDump);
        assertEquals(PRF_RESULTS_2_HEX, ByteBufUtil.hexDump(loginPresentDump));

        var recoveryRequestBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(CLIENT_SIGN_2_HEX));
        var recoveryRequest = assertDoesNotThrow(() -> ClientPRFRequest.load(recoveryRequestBytes));
        var recoveryPresent = server.makePRFPresent(USER_UUID, recoveryRequest).toCompletableFuture().join();
        var recoveryPresentDump = Unpooled.buffer();
        recoveryPresent.dump(recoveryPresentDump);
        assertEquals(PRF_RESULTS_2_HEX, ByteBufUtil.hexDump(recoveryPresentDump));

        var absentRequestBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(CLIENT_SIGN_3_HEX));
        var absentRequest = assertDoesNotThrow(() -> ClientPRFRequest.load(absentRequestBytes));
        var absentPresent = server.makePRFPresent(FAKE_UUID, absentRequest).toCompletableFuture().join();
        var absentPresentDump = Unpooled.buffer();
        new ServerPRFAbsent(absentPresent).dump(absentPresentDump);
        assertEquals(PRF_RESULTS_3_HEX, ByteBufUtil.hexDump(absentPresentDump));
        var expectedEntryBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_LOOKUP_HEX));
        var expectedEntry = assertDoesNotThrow(() -> IdentityUserEntry.load(expectedEntryBytes));
        assertNotEquals(expectedEntry.envelope(), absentPresent.envelope());
        assertEquals(0, rngBytes.readableBytes());
    }

    @Test
    void section4_signature_authorization_returns_valid_signature_with_expected_role_serialization() {
        var db = new MemoryDB();
        var rngSource = "b78d677a7b3a5248aac33dfeb01c4d5bdb84657279a5cf8bf8385fc2d98e6d6741d6763f8a350aad3d4f334418db" +
                "038bc91dead2f13dd1bdfe76ea3dccda0452bffd2fd20dc56c96c87b2eddff00fb8e88fd1283247c0ca0bf85b2b1321eb7e9";
        var rngBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(rngSource));
        var server = new VoteServerContext(SEED.toCharArray(), db, rngBytes::readLongLE);
        var entryBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_LOOKUP_HEX));
        var entry = assertDoesNotThrow(() -> IdentityUserEntry.load(entryBytes));
        db.accounts.put(USER_UUID, entry);
        db.works.add(new WorkInformation(WORK_UUID, VOTE_INFO_TEXT, "#demo"));

        var commitBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(CLIENT_COMMIT_HEX));
        var commit = assertDoesNotThrow(() -> ClientPointCommit.load(commitBytes));
        var signature = server.makeSignature(USER_UUID, commit).toCompletableFuture().join();
        assertEquals(ROLES, signature.roles());
        var signatureDump = Unpooled.buffer();
        signature.dump(signatureDump);
        assertEquals(SIGN_RESPONSE_HEX, ByteBufUtil.hexDump(signatureDump));
        var proofBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(BLINDED_PROOF_HEX));
        var proof = assertDoesNotThrow(() -> IdentityBlindProof.load(proofBytes));
        assertEquals(VOTE_INFO.levels(), proof.info().levels());
        assertEquals(VOTE_INFO.comments(), proof.info().comments());
        assertEquals(0, rngBytes.readableBytes());
    }

    @Test
    void section5_anonymous_voting_accepts_valid_blind_proof_and_stores_vote() {
        var db = new MemoryDB();
        var rngSource = "b78d677a7b3a5248aac33dfeb01c4d5bdb84657279a5cf8bf8385fc2d98e6d6741d6763f8a350aad3d4f334418db" +
                "038bc91dead2f13dd1bdfe76ea3dccda0452bffd2fd20dc56c96c87b2eddff00fb8e88fd1283247c0ca0bf85b2b1321eb7e9";
        var rngBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(rngSource));
        var server = new VoteServerContext(SEED.toCharArray(), db, rngBytes::readLongLE);
        var entryBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_LOOKUP_HEX));
        var entry = assertDoesNotThrow(() -> IdentityUserEntry.load(entryBytes));
        db.accounts.put(USER_UUID, entry);
        db.works.add(new WorkInformation(WORK_UUID, VOTE_INFO_TEXT, "#demo"));

        var commitBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(CLIENT_COMMIT_HEX));
        var commit = assertDoesNotThrow(() -> ClientPointCommit.load(commitBytes));
        var signature = server.makeSignature(USER_UUID, commit).toCompletableFuture().join();
        var signatureDump = Unpooled.buffer();
        signature.dump(signatureDump);
        assertEquals(SIGN_RESPONSE_HEX, ByteBufUtil.hexDump(signatureDump));
        var proofBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(BLINDED_PROOF_HEX));
        var proof = assertDoesNotThrow(() -> IdentityBlindProof.load(proofBytes));
        assertTrue(VoteChallenges.validate(server, proof));

        server.readBlindProof(proof).toCompletableFuture().join();

        assertEquals(1, db.votes.size());
        var voteDump = Unpooled.buffer();
        db.votes.getFirst().dump(voteDump);
        assertEquals(BLINDED_PROOF_HEX, ByteBufUtil.hexDump(voteDump));
        assertEquals(0, rngBytes.readableBytes());
    }

    @Test
    void section6_revocation_stores_revocation_and_purges_matching_votes() {
        var db = new MemoryDB();
        var rngSource = "b78d677a7b3a5248aac33dfeb01c4d5bdb84657279a5cf8bf8385fc2d98e6d6741d6763f8a350aad3d4f334418db" +
                "038bc91dead2f13dd1bdfe76ea3dccda0452bffd2fd20dc56c96c87b2eddff00fb8e88fd1283247c0ca0bf85b2b1321eb7e9";
        var rngBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(rngSource));
        var server = new VoteServerContext(SEED.toCharArray(), db, rngBytes::readLongLE);
        var entryBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_LOOKUP_HEX));
        var entry = assertDoesNotThrow(() -> IdentityUserEntry.load(entryBytes));
        db.accounts.put(USER_UUID, entry);
        db.works.add(new WorkInformation(WORK_UUID, VOTE_INFO_TEXT, "#demo"));

        var commitBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(CLIENT_COMMIT_HEX));
        var commit = assertDoesNotThrow(() -> ClientPointCommit.load(commitBytes));
        var signature = server.makeSignature(USER_UUID, commit).toCompletableFuture().join();
        var signatureDump = Unpooled.buffer();
        signature.dump(signatureDump);
        assertEquals(SIGN_RESPONSE_HEX, ByteBufUtil.hexDump(signatureDump));
        var proofBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(BLINDED_PROOF_HEX));
        var proof = assertDoesNotThrow(() -> IdentityBlindProof.load(proofBytes));
        server.readBlindProof(proof).toCompletableFuture().join();

        var revocationBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(CLIENT_REVOKE_HEX));
        var revocation = assertDoesNotThrow(() -> ClientRevocation.load(revocationBytes));
        server.readRevocation(USER_UUID, revocation).toCompletableFuture().join();

        assertEquals(1, db.revocations.size());
        assertEquals(1, db.votes.size());
        var revocationDump = Unpooled.buffer();
        db.revocations.getFirst().dump(revocationDump);
        assertEquals(CLIENT_REVOKE_HEX, ByteBufUtil.hexDump(revocationDump));
        assertEquals(0, rngBytes.readableBytes());
    }

    private static final class MemoryDB implements DBService {
        private final Map<UUID, IdentityUserEntry> accounts = new HashMap<>();
        private final List<ClientRevocation> revocations = new ArrayList<>();
        private final List<IdentityBlindProof> votes = new ArrayList<>();
        private final List<WorkInformation> works = new ArrayList<>();

        @Override
        public CompletionStage<Optional<IdentityUserEntry>> fetchAccount(UUID uuid) {
            return CompletableFuture.completedFuture(Optional.ofNullable(this.accounts.get(uuid)));
        }

        @Override
        public CompletionStage<List<ClientRevocation>> fetchRevocations() {
            return CompletableFuture.completedFuture(List.copyOf(this.revocations));
        }

        @Override
        public CompletionStage<List<WorkInformation>> fetchWorks() {
            return CompletableFuture.completedFuture(List.copyOf(this.works));
        }

        @Override
        public CompletionStage<Integer> purgeVotes(List<HashCode> indexes) {
            var before = this.votes.size();
            this.votes.removeIf(vote -> indexes.contains(vote.id().index()));
            return CompletableFuture.completedFuture(before - this.votes.size());
        }

        @Override
        public CompletionStage<Void> storeRevocation(ClientRevocation revocation) {
            this.revocations.add(revocation);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletionStage<Void> storeVote(IdentityBlindProof vote) {
            this.votes.add(vote);
            return CompletableFuture.completedFuture(null);
        }
    }
}
