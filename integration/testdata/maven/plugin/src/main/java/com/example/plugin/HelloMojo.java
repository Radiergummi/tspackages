package com.example.plugin;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.Mojo;

/** Logs a greeting. */
@Mojo(name = "hello", requiresProject = false)
public class HelloMojo extends AbstractMojo {
    @Override
    public void execute() {
        getLog().info("hello");
    }
}
