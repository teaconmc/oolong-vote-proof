package org.teacon.ovp.storage;

import com.google.common.hash.HashCode;
import org.teacon.ovp.payload.ClientRevocation;
import org.teacon.ovp.payload.IdentityBlindProof;
import org.teacon.ovp.payload.IdentityUserEntry;
import org.teacon.ovp.util.WorkInformation;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public interface DBService {
    default CompletionStage<Optional<IdentityUserEntry>> fetchAccount(UUID uuid) {
        return CompletableFuture.failedStage(new UnsupportedOperationException());
    }

    default CompletionStage<List<ClientRevocation>> fetchRevocations() {
        return CompletableFuture.failedStage(new UnsupportedOperationException());
    }

    default CompletionStage<List<IdentityBlindProof>> fetchVotes(List<HashCode> indexes) {
        return CompletableFuture.failedStage(new UnsupportedOperationException());
    }

    default CompletionStage<List<WorkInformation>> fetchWorks() {
        return CompletableFuture.failedStage(new UnsupportedOperationException());
    }

    default CompletionStage<Integer> purgeVotes(List<HashCode> indexes) {
        return CompletableFuture.failedStage(new UnsupportedOperationException());
    }

    default CompletionStage<Boolean> purgeWork(UUID work) {
        return CompletableFuture.failedStage(new UnsupportedOperationException());
    }

    default CompletionStage<Void> storeAccount(IdentityUserEntry entry) {
        return CompletableFuture.failedStage(new UnsupportedOperationException());
    }

    default CompletionStage<Void> storeRevocation(ClientRevocation revocation) {
        return CompletableFuture.failedStage(new UnsupportedOperationException());
    }

    default CompletionStage<Void> storeVote(IdentityBlindProof vote) {
        return CompletableFuture.failedStage(new UnsupportedOperationException());
    }

    default CompletionStage<Void> storeWork(WorkInformation information) {
        return CompletableFuture.failedStage(new UnsupportedOperationException());
    }
}
