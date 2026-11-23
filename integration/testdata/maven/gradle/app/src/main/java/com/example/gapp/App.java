package com.example.gapp;

/** Uses the library, so compiling it proves it resolved. */
public final class App {
    private App() {}

    public static void main(String[] args) {
        System.out.println(com.example.glib.Lib.value());
    }
}
