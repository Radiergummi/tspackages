// Gen prints testdata/versions.txt sorted by Maven's ComparableVersion, one
// version per line; equal versions keep their input order. Run from the
// package directory:
//
//	java -cp $(brew --prefix maven)/libexec/lib/maven-artifact-3.10.2.jar testdata/Gen.java > testdata/versions.golden
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.apache.maven.artifact.versioning.ComparableVersion;

public class Gen {
    public static void main(String[] args) throws Exception {
        List<String> versions = new ArrayList<>();
        for (String line : Files.readAllLines(Path.of("testdata/versions.txt"))) {
            if (!line.isEmpty()) {
                versions.add(line);
            }
        }
        versions.sort((a, b) -> new ComparableVersion(a).compareTo(new ComparableVersion(b)));
        for (String v : versions) {
            System.out.println(v);
        }
    }
}
