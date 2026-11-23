package com.example.lib;

/** A deployed library. */
public final class Lib {
    private Lib() {}

    /**
     * Returns the value this build was made with.
     *
     * @return the value
     */
    public static String value() {
        return "{{.Body}}";
    }
}
