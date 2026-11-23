plugins {
    java
}

{{.Repositories}}

dependencies {
    implementation("{{.Dependency}}")
}

// Prints the resolved version of every dependency, for the test to read.
tasks.register("resolved") {
    val artifacts = configurations.runtimeClasspath.get().incoming.artifacts.resolvedArtifacts
    doLast {
        artifacts.get().forEach { println("resolved " + it.id.componentIdentifier.displayName + " " + it.file.name) }
    }
}
