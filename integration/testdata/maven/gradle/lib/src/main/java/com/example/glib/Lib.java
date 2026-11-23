package com.example.glib;

/** A published library. */
public final class Lib {
    private Lib() {}

    /** Returns the value this build was made with. */
    public static String value() {
        return "{{.Body}}";
    }
}
