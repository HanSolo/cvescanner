package eu.hansolo.cvescanner;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashSet;
import java.util.Set;


public class ListFileVisitor extends SimpleFileVisitor {
    public Set<String> jarFiles = new HashSet<>();

    @Override public FileVisitResult visitFile(final Object file, final BasicFileAttributes attrs) throws IOException {
        final String filename = file.toString();
        if (filename.endsWith("jar")) { jarFiles.add(filename); }
        return FileVisitResult.CONTINUE;
    }
}
