package org.example.seed.plugin;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.Mojo;

/** Does nothing; it makes the module a plugin. */
@Mojo(name = "seed")
public class SeedMojo extends AbstractMojo {
    @Override
    public void execute() {
        getLog().info("seed");
    }
}
