plugins {
    id("java-library")
    id("maven-publish")
}

apply {
    version = "0.1.0"
    group = "org.teacon"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.google.guava:guava:33.5.0-jre")
    implementation("io.netty:netty-buffer:4.2.7.Final")
    testImplementation("org.junit.jupiter:junit-jupiter:5.14.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.14.3")
}

java {
    toolchain.languageVersion = JavaLanguageVersion.of(21)
}

tasks.test {
    useJUnitPlatform()
}

tasks.processResources {
    from(file("LICENSE")) { into("META-INF/").rename { "$it.txt" } }
}

publishing {
    publications.create<MavenPublication>("mavenJava") {
        groupId = "org.teacon"
        artifactId = "oolong-vote-proof"
        version = "${project.version}"
        pom {
            name.set("OolongVoteProof")
            url.set("https://github.com/teaconmc/oolong-vote-proof")
            description.set("Java implementation of a PS-signature-based anonymous voting and identifier scheme")
            licenses {
                license {
                    name.set("GNU Lesser General Public License, Version 3.0")
                    url.set("https://www.gnu.org/licenses/lgpl-3.0.txt")
                }
            }
            developers {
                developer {
                    id.set("teaconmc")
                    name.set("TeaConMC")
                    email.set("contact@teacon.org")
                }
                developer {
                    id.set("ustc-zzzz")
                    name.set("Yanbing Zhao")
                    email.set("zzzz.mail.ustc@gmail.com")
                }
            }
            issueManagement {
                system.set("GitHub Issues")
                url.set("https://github.com/teaconmc/oolong-vote-proof/issues")
            }
            scm {
                url.set("https://github.com/teaconmc/oolong-vote-proof")
                connection.set("scm:git:git://github.com/teaconmc/oolong-vote-proof.git")
                developerConnection.set("scm:git:ssh://github.com/teaconmc/oolong-vote-proof.git")
            }
        }
        artifact(tasks.jar)
    }
}
