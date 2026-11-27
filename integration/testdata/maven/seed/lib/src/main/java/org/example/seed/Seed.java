package org.example.seed;

import org.slf4j.LoggerFactory;

/** Uses the public dependency the tests resolve. */
public final class Seed {
    private Seed() {}

    /**
     * Returns the logger factory's name.
     *
     * @return the class name
     */
    public static String name() {
        return LoggerFactory.class.getName();
    }
}
