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
