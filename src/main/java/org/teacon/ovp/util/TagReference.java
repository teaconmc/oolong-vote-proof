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

package org.teacon.ovp.util;

import java.util.regex.Pattern;

public final class TagReference implements Comparable<TagReference> {
    private static final Pattern PATH_PATTERN = Pattern.compile("[a-z0-9/._-]+");
    private static final Pattern NAMESPACE_PATTERN = Pattern.compile("[a-z0-9._-]+");

    private final String path;
    private final String namespace;
    private final String concatenation;

    public TagReference(String namespace, String path) {
        this.path = path;
        this.namespace = namespace;
        this.concatenation = namespace + ":" + path;
        if (!PATH_PATTERN.matcher(this.path).matches()) {
            throw new IllegalArgumentException("Invalid path: " + this.path);
        }
        if (!NAMESPACE_PATTERN.matcher(this.namespace).matches()) {
            throw new IllegalArgumentException("Invalid namespace: " + this.namespace);
        }
        if (this.concatenation.length() > 0x3FFF) {
            throw new IllegalArgumentException("Reference too long (max " + 0x3FFF + " bytes)");
        }
    }

    public TagReference(String concatenation) {
        if (concatenation.length() > 0x3FFF) {
            throw new IllegalArgumentException("Reference too long (max " + 0x3FFF + " bytes)");
        }
        var colonIndex = concatenation.indexOf(':');
        if (colonIndex == -1) {
            throw new IllegalArgumentException("Invalid reference: " + concatenation + " (must contain a colon)");
        }
        this.concatenation = concatenation;
        this.namespace = concatenation.substring(0, colonIndex);
        this.path = concatenation.substring(colonIndex + 1);
        if (!PATH_PATTERN.matcher(this.path).matches()) {
            throw new IllegalArgumentException("Invalid path: " + this.path);
        }
        if (!NAMESPACE_PATTERN.matcher(this.namespace).matches()) {
            throw new IllegalArgumentException("Invalid namespace: " + this.namespace);
        }
    }

    public String path() {
        return this.path;
    }

    public String namespace() {
        return this.namespace;
    }

    public int length() {
        return this.concatenation.length();
    }

    @Override
    public String toString() {
        return this.concatenation;
    }

    @Override
    public boolean equals(Object o) {
        return this == o || o instanceof TagReference that && this.concatenation.equals(that.concatenation);
    }

    @Override
    public int hashCode() {
        return this.concatenation.hashCode();
    }

    @Override
    public int compareTo(TagReference o) {
        var i = this.namespace.compareTo(o.namespace);
        return i == 0 ? this.path.compareTo(o.path) : i;
    }
}
