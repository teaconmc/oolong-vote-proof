package org.teacon.ovp.payload;

import com.google.common.collect.ImmutableSortedSet;
import com.google.common.collect.Ordering;
import io.netty.buffer.ByteBuf;
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.util.BLS12381;
import org.teacon.ovp.util.TagReference;

import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.UUID;

public final class IdentityUserEntry {
    public static IdentityUserEntry load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new IdentityUserEntry(input);
        } catch (RuntimeException e) {
            throw new SignatureException("invalid identity user entry", e);
        }
    }

    public UUID uuid() {
        return this.uuid;
    }

    public String envelope() {
        return this.envelope;
    }

    public SortedSet<TagReference> roles() {
        return this.roles;
    }

    public void dump(ByteBuf output) {
        output.writeLong(this.uuid.getMostSignificantBits()).writeLong(this.uuid.getLeastSignificantBits());
        BLS12381.pointToSignature(this.commit, output);
        BLS12381.decodeEnvelope(this.envelope, output);
        for (var role : this.roles) {
            BLS12381.stringToBytes(false, role.toString(), output);
        }
        BLS12381.stringToBytes(false, "", output);
    }

    UUID uuid;
    ECP commit;
    String envelope;
    ImmutableSortedSet<TagReference> roles;

    IdentityUserEntry(UUID uuid, ClientPRFOverride override, Set<TagReference> roles) {
        this.uuid = uuid;
        this.commit = override.s;
        this.envelope = override.envelope();
        this.roles = ImmutableSortedSet.copyOf(Ordering.natural(), roles);
    }

    IdentityUserEntry(ByteBuf input) {
        this.uuid = new UUID(input.readLong(), input.readLong());
        this.commit = BLS12381.signatureToPoint(input);
        this.envelope = BLS12381.encodeEnvelope(input);
        var roleSet = new TreeSet<TagReference>(Ordering.natural());
        var str = BLS12381.bytesToString(false, input);
        while (!str.isEmpty()) {
            var fresh = roleSet.add(new TagReference(str));
            if (!fresh || !roleSet.last().toString().equals(str)) {
                throw new IllegalArgumentException("unsorted tag references");
            }
            str = BLS12381.bytesToString(false, input);
        }
        this.roles = ImmutableSortedSet.copyOfSorted(roleSet);
    }
}
