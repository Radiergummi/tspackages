package com.example.app;

/** Uses each dependency, so compiling it proves they resolved. */
public final class App {
    private App() {}

    public static void main(String[] args) {
{{- range .Deps}}{{if .Use}}
        System.out.println({{.Use}});
{{- end}}{{end}}
    }
}
