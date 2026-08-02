# JavaParser CLI (optional)

VulnGraph can analyze Java codebases using a regex fallback, but accuracy improves
when the JavaParser CLI JAR is available.

## Download

1. Download **javaparser-core-3.25.x** (or newer 3.25 release) from Maven Central:

   https://repo1.maven.org/maven2/com/github/javaparser/javaparser-core/3.25.10/javaparser-core-3.25.10.jar

2. If you have a JavaParser CLI fat jar, place it in this directory as:

   ```
   tools/javaparser-cli.jar
   ```

   VulnGraph invokes:

   ```bash
   java -jar tools/javaparser-cli.jar <path-to-file.java>
   ```

   and expects JSON output describing methods (names, line numbers, annotations, bodies).

## Requirements

- **Java runtime** (`java` on PATH)
- **JDK** (`javap` on PATH) — checked for availability; the bridge falls back to regex if the JAR is missing

## Without the JAR

No setup is required. The bridge uses regex heuristics to detect:

- Entry points (`@RequestMapping`, `main()`, etc.)
- Sinks (`.execute()`, `Runtime.exec()`, etc.)
- Guards (`@Valid`, `validate*`, etc.)

Place `.java` files in your project and scan with `/api/cve/scan`.
