package eu.hansolo.cvescanner;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;


public class Helper {
    public static final String  HOME_FOLDER = new StringBuilder(System.getProperty("user.home")).append(File.separator).toString();

    public static List<Jar> getUsersJars() {
        final Set<String> jarFiles = getJarsInHomeFolder();
        final List<Jar>   jars     = new ArrayList<>();
        jarFiles.forEach(jarFile -> {
            String filename = jarFile.substring(jarFile.lastIndexOf(File.separator) + 1);
            String path     = jarFile.substring(0, jarFile.lastIndexOf(File.separator));
            String version  = getVersionFromJar(jarFile);
            if (!version.isEmpty()) {
                jars.add(new Jar(path, filename, version));
            }
        });
        return jars;
    }

    public static Set<String> getJarsInHomeFolder() {
        return getJarsInFolder(HOME_FOLDER);
    }
    public static Set<String> getJarsInFolder(final String path) {
        final Path dir = Paths.get(path);
        final ListFileVisitor listFileVisitor = new ListFileVisitor();
        try {
            Files.walkFileTree(dir, listFileVisitor);
        } catch(FileSystemException e) {
            e.printStackTrace();
        } catch(UncheckedIOException e) {
            e.printStackTrace();
        } catch(IOException e) {
            e.printStackTrace();
        }
        return listFileVisitor.jarFiles;
    }

    public static final String getVersionFromJar(final String jarFileName) {
        try {
            final JarFile                         jarFile                  = new JarFile(jarFileName);
            final Manifest                        manifest                 = jarFile.getManifest();
            if (null == manifest) { return ""; }
            final Attributes                      attributes               = manifest.getMainAttributes();
            final Optional<Entry<Object, Object>> optImplementationVersion = attributes.entrySet().stream().filter(entry -> entry.getKey().toString().equalsIgnoreCase("Implementation-Version")).findFirst();
            final String                          implementationVersion    = optImplementationVersion.isPresent() ? optImplementationVersion.get().getValue().toString() : "";
            if (implementationVersion.isEmpty()) {
                final Optional<Entry<Object, Object>> optBundleVersion = attributes.entrySet().stream().filter(entry -> entry.getKey().toString().equalsIgnoreCase("Bundle-Version")).findFirst();
                final String                          bundleVersion    = optBundleVersion.isPresent() ? optBundleVersion.get().getValue().toString() : "";
                return bundleVersion;
            } else {
                return implementationVersion;
            }
        } catch(IOException e) {
            return "";
        }
    }
}
