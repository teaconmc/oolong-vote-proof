package org.teacon.ovp.payload;

import com.google.common.collect.ImmutableSortedSet;
import com.google.common.collect.Ordering;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.teacon.ovp.miracl.core.BLS12381.BIG;
import org.teacon.ovp.miracl.core.BLS12381.ECP;
import org.teacon.ovp.util.BLS12381;
import org.teacon.ovp.util.TagReference;

import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.util.Collection;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.random.RandomGenerator;

public final class IdentitySignature {
    public static IdentitySignature load(ByteBuf input) throws GeneralSecurityException {
        try {
            return new IdentitySignature(input);
        } catch (RuntimeException e) {
            throw new SignatureException("invalid server signature", e);
        }
    }

    final ImmutableSortedSet<TagReference> roles;
    final int rolesByteCount;
    final BIG rolesHash;
    final ECP a;
    final ECP b;

    public SortedSet<TagReference> roles() {
        return this.roles;
    }

    public void dump(ByteBuf output) {
        for (var role : this.roles) {
            BLS12381.stringToBytes(false, role.toString(), output);
        }
        BLS12381.stringToBytes(false, "", output);
        BLS12381.pointToSignature(this.a, output);
        BLS12381.pointToSignature(this.b, output);
    }

    IdentitySignature(ServerSecretKey serverSecret, ClientPointCommit blind,
                      Collection<TagReference> roles, RandomGenerator rng) {
        this.roles = ImmutableSortedSet.copyOf(Ordering.natural(), roles);
        var rolesHash = Unpooled.buffer();
        for (var role : this.roles) {
            BLS12381.stringToBytes(false, role.toString(), rolesHash);
        }
        BLS12381.stringToBytes(false, "", rolesHash);
        this.rolesByteCount = rolesHash.readableBytes();
        this.rolesHash = BLS12381.hashToScalar(rolesHash, this.rolesByteCount);
        var r = BLS12381.randomToField(rng);
        this.a = ECP.generator().mul(r);
        this.b = this.a.mul(serverSecret.w).mul(this.rolesHash);
        this.b.add(this.a.mul(serverSecret.x));
        this.b.add(blind.s.mul(r).mul(serverSecret.y));
    }

    IdentitySignature(IdentitySignature signature, RandomGenerator rng) {
        this.roles = signature.roles;
        this.rolesHash = signature.rolesHash;
        this.rolesByteCount = signature.rolesByteCount;
        var r = BLS12381.randomToField(rng);
        this.a = signature.a.mul(r);
        this.b = signature.b.mul(r);
    }

    IdentitySignature(ByteBuf input) {
        var rolesIndex = input.readerIndex();
        var roles = new TreeSet<TagReference>(Ordering.natural());
        var str = BLS12381.bytesToString(false, input);
        while (!str.isEmpty()) {
            var fresh = roles.add(new TagReference(str));
            if (!fresh || !roles.last().toString().equals(str)) {
                throw new IllegalArgumentException("unsorted tag references");
            }
            str = BLS12381.bytesToString(false, input);
        }
        this.roles = ImmutableSortedSet.copyOfSorted(roles);
        this.rolesByteCount = input.readerIndex() - rolesIndex;
        this.rolesHash = BLS12381.hashToScalar(input.slice(rolesIndex, this.rolesByteCount), this.rolesByteCount);
        this.a = BLS12381.signatureToPoint(input);
        this.b = BLS12381.signatureToPoint(input);
    }
}
