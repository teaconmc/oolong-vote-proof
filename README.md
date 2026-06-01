# OolongVoteProof

[![](https://jitpack.io/v/org.teacon/oolong-vote-proof.svg)](https://jitpack.io/#org.teacon/oolong-vote-proof)

OolongVoteProof is a Java implementation of a PS-signature-based anonymous
voting and identifier scheme. The description of the protocol is available
in [docs/README.md](docs/README.md).

## Requirements

OolongVoteProof requires Java 21 or later.

## Installation

OolongVoteProof is now available under JitPack. Add JitPack repository and
then and then depend on the published artifact.

### Gradle Kotlin DSL

```kotlin
repositories {
    mavenCentral()
    maven("https://jitpack.io")
}

dependencies {
    implementation("org.teacon:oolong-vote-proof:<version>")
}
```

### Gradle Groovy DSL

```groovy
repositories {
    mavenCentral()
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation 'org.teacon:oolong-vote-proof:<version>'
}
```

### Maven

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependencies>
    <dependency>
        <groupId>org.teacon</groupId>
        <artifactId>oolong-vote-proof</artifactId>
        <version>${oolong-vote-proof.version}</version>
    </dependency>
</dependencies>
```

Replace `<version>` or `${oolong-vote-proof.version}` with Git tag, commit
hash, or other version shown on the JitPack page.
