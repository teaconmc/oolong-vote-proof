plugins {
    id("java-library")
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
    testImplementation("org.junit.jupiter:junit-jupiter:5.14.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.14.3")
}

java {
    toolchain.languageVersion = JavaLanguageVersion.of(21)
}

tasks.test {
    useJUnitPlatform()
}
