plugins {
    id("java")
}

group = "com.github.reganjohn"
version = "1.0-SNAPSHOT"

base {
    archivesName.set("iam")
}

val javaVersion = JavaVersion.VERSION_11

repositories {
    mavenCentral()
    mavenLocal()
}

dependencies {
    implementation("org.jetbrains:annotations:26.0.2-1")
    implementation("com.fasterxml.jackson.core:jackson-core:2.20.0")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.20.0")
    implementation("com.google.crypto.tink:tink:1.12.0")
    implementation("com.nimbusds:nimbus-jose-jwt:10.9")
    implementation("org.bouncycastle:bcprov-lts8on:2.73.10")
    implementation("com.adamorgan:JNT:1.0.0_DEV")
    implementation("com.reganjohn:C4J:1.0.0_DEV")

    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.jar {
    manifest {
        attributes["Main-Class"] = "com.github.reganjohn.iam.internal.IAMImpl"
    }

    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")

    from({
        configurations.runtimeClasspath.get()
                .filter { it.name.endsWith("jar") }
                .map { zipTree(it) }
    })
}

tasks.test {
    useJUnitPlatform()
}
