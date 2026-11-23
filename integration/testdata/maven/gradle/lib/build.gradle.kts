plugins {
    `java-library`
    `maven-publish`
    signing
}

group = "{{.Group}}"
version = "{{.Version}}"

java {
    withSourcesJar()
}

{{.Repositories}}

publishing {
    publications {
        create<MavenPublication>("lib") {
            from(components["java"])
        }
    }
}

{{.Publishing}}

val signingKey = providers.environmentVariable("SIGNING_KEY")
if (signingKey.isPresent) {
    signing {
        useInMemoryPgpKeys(signingKey.get(), "")
        sign(publishing.publications)
    }
}
