/*
 * Copyright (C) 2026 TeaConMC <contact@teacon.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package org.teacon.ovp.payload;

import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;
import org.teacon.ovp.util.TagReference;
import org.teacon.ovp.util.VoteInformation;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.random.RandomGenerator;

import static org.junit.jupiter.api.Assertions.*;

class IdentityBlindProofTest {
    private static final UUID WORK = UUID.fromString("89abcdef-0123-4567-89ab-cdef01234567");
    private static final String CLIENT_SECRET_HEX = "15c026745a89f94dc78abebf65579b292c8c0924b2603c0736cfba6d28a47a2f";
    private static final String SERVER_SECRET_HEX = "267cc15949dcf8ef55f0a325b8f56e32d296b41251a7c94a9101b1ad41106199" +
            "3410820adc72d75744970568546b5a7a5e2305b7b48a52aff2b43f275f58c37746ad2ad93622109df93a0666cdc5dd8c899077f4" +
            "9f46f1fce99bd1520b3a41975771318129301ae63bbe78ae8628c99139b69e16153e92217ede3f00c2ec17c4";
    private static final String ID_DERIVATION_HEX = "ad400d032aefad184d33f14f8debabf5bfe330cd0392f182efe74c81d1be2e65" +
            "cf5a704258f290afd6c6367b4b96f8c1";
    private static final String IDENTITY_SIGN_HEX = "03613a7807613a782f792e7a03663a6219663a622f766572792e6c6f6e675f73" +
            "65676d656e742d31323304663a6232106c6f6e672e6e616d6573706163653a61106c6f6e672e6e616d6573706163653a7a037a3a" +
            "611c7a3a615f7265616c6c792f6c6f6e672f706174682e7365676d656e74047a7a3a3000a967b927e1ef537517c9aa3664e3b31d" +
            "6a38721a9c23212615a301e3e8b43f35cdf1da7499695de8f460b4883a732f6783b4d6eb939ce3227008136c5361c1ffccad5833" +
            "f5cbd04582922eb34ce63ef4a5efa5a51e2caeb2e94a5bc2d907f374";
    private static final String BLINDED_PROOF_HEX = "89abcdef0123456789abcdef01234567ad400d032aefad184d33f14f8debabf5" +
            "bfe330cd0392f182efe74c81d1be2e65cf5a704258f290afd6c6367b4b96f8c1430003613a61400003613a7a3c0003623a78fffe" +
            "056669727374067365636f6e6403613a7807613a782f792e7a03663a6219663a622f766572792e6c6f6e675f7365676d656e742d" +
            "31323304663a6232106c6f6e672e6e616d6573706163653a61106c6f6e672e6e616d6573706163653a7a037a3a611c7a3a615f72" +
            "65616c6c792f6c6f6e672f706174682e7365676d656e74047a7a3a3000ab9ed0df4b2425e22a84e7a2f7469baa6f80107462221b" +
            "cc26770d5b345b1a781503036d2acc7a307dfb2deb5d46e0fc871864c00a9078ce80cdaef2db9bed0c7d2074f8b36b2be7d973d9" +
            "cc74f7a4325761c5a239ff251cd80f3c0d39d4b59735a65c135df33773f1035dd301c4517d3339b4701a53d4b1570d5f6cd27ef6" +
            "e4461e5c47259062a9451629113714b7c46f210db7b8d325da727334e63ffbf565";
    public static final VoteInformation VOTE_INFO = new VoteInformation(Map.of(
            new TagReference("a", "z"), VoteInformation.Level.TWO,
            new TagReference("a", "a"), VoteInformation.Level.THREE_HALF,
            new TagReference("b", "x"), VoteInformation.Level.ONE), List.of("first", "second"));

    @Test
    public void from_work_id_info_accessors_expose_expected_values() {
        var clientSk = new ClientSecretKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(CLIENT_SECRET_HEX)));
        var serverSk = new ServerSecretKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_SECRET_HEX)));
        var serverPk = new ServerPublicKey(serverSk);
        var ctx = new VoteClientContext(serverPk, RandomGenerator.of("SecureRandom")).readSecretKey(clientSk);
        var sig = new IdentitySignature(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(IDENTITY_SIGN_HEX)));

        var proof = ctx.makeIdentityBlindProof(WORK, VOTE_INFO, sig);

        assertEquals(WORK, proof.work());
        var idDump = Unpooled.buffer(48);
        proof.id().dump(idDump);
        assertEquals(ID_DERIVATION_HEX, ByteBufUtil.hexDump(idDump));
        assertEquals(VOTE_INFO.levels(), proof.info().levels());
        assertEquals(VOTE_INFO.comments(), proof.info().comments());
        assertEquals(sig.roles(), proof.signature().roles());
    }

    @Test
    public void load_accessors_and_dump_roundTrip_match_vector() {
        var loaded = new IdentityBlindProof(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(BLINDED_PROOF_HEX)));

        assertEquals(WORK, loaded.work());
        var idDump = Unpooled.buffer(48);
        loaded.id().dump(idDump);
        assertEquals(ID_DERIVATION_HEX, ByteBufUtil.hexDump(idDump));
        assertEquals(List.of("first", "second"), loaded.info().comments());
        assertEquals(List.of("a:a", "a:z", "b:x"),
                loaded.info().levels().keySet().stream().map(TagReference::toString).toList());

        var dumpedAgain = Unpooled.buffer(BLINDED_PROOF_HEX.length() / 2);
        loaded.dump(dumpedAgain);
        assertEquals(BLINDED_PROOF_HEX, ByteBufUtil.hexDump(dumpedAgain));
    }

    @Test
    public void constructor_fromByteBuf_rejects_invalid_parse_input() {
        var bad = Unpooled.buffer(1).writeByte(0x01);
        assertThrows(RuntimeException.class, () -> new IdentityBlindProof(bad));
    }

    @Test
    public void identityBlindProof_can_be_constructed_loaded_and_verified_with_voteChallenges() {
        var clientSk = new ClientSecretKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(CLIENT_SECRET_HEX)));
        var serverSk = new ServerSecretKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_SECRET_HEX)));
        var serverPk = new ServerPublicKey(serverSk);
        var ctx = new VoteClientContext(serverPk, RandomGenerator.of("SecureRandom")).readSecretKey(clientSk);

        var sig = new IdentitySignature(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(IDENTITY_SIGN_HEX)));

        var entropyBytesHex = "ac1d5c5a9c2ae5a1a241f78f9b4f1376a5cb8b4804e3639ab69bf07c45237b50b9c5039508a6d00c0fa88d" +
                "d30e0ae213b84dad795f7768de43f5584364dfec8fd2b68924c3b2ec3101be6aaf730dceccc0b583e1a1fb5d9def78ec6ee5" +
                "3a5fba76b6ea67159e57536763442cf9b026c9302cba54e325ce41c16eaef1237085a7ec79df17ed685a3096563c925c3c3a" +
                "72efb9846b5ae106921735425323e3edb5df02eae370050cd2ad13513cf2f5db32cefe730076410f8e428b12fec30d077e";
        var entropyBytes = Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(entropyBytesHex));
        var entropy = (RandomGenerator) entropyBytes::readLongLE;

        var proof = new IdentityBlindProof(ctx, WORK, VOTE_INFO, sig, entropy);
        var dump = Unpooled.buffer(BLINDED_PROOF_HEX.length() / 2);
        proof.dump(dump);
        assertEquals(BLINDED_PROOF_HEX, ByteBufUtil.hexDump(dump));
        var idDump = Unpooled.buffer(48);
        proof.id().dump(idDump);
        assertEquals(ID_DERIVATION_HEX, ByteBufUtil.hexDump(idDump));

        var loaded = new IdentityBlindProof(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(BLINDED_PROOF_HEX)));
        var dumpedAgain = Unpooled.buffer(BLINDED_PROOF_HEX.length() / 2);
        loaded.dump(dumpedAgain);
        assertEquals(BLINDED_PROOF_HEX, ByteBufUtil.hexDump(dumpedAgain));
    }

    @Test
    public void voteChallenges_validate_rejects_tampered_identity_blind_proof() {
        var serverSk = new ServerSecretKey(Unpooled.wrappedBuffer(ByteBufUtil.decodeHexDump(SERVER_SECRET_HEX)));
        var serverPk = new ServerPublicKey(serverSk);

        var encoded = ByteBufUtil.decodeHexDump(BLINDED_PROOF_HEX);
        var tampered = Unpooled.wrappedBuffer(encoded).setByte(encoded.length - 1, 0x00);
        var badProof = new IdentityBlindProof(tampered);
        var ctx = new VoteClientContext(serverPk, RandomGenerator.of("SecureRandom"));
        assertFalse(VoteChallenges.validate(ctx, badProof));
    }
}
