package eu.hansolo.cvescanner;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import eu.hansolo.jdktools.versioning.VersionNumber;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Month;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.stream.Collectors;


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

    public static final String getTextFromUrl(final String uri, final Charset charset) {
        try (var stream = URI.create(uri).toURL().openStream()) {
            return new String(stream.readAllBytes(), charset);
        } catch(Exception e) {
            return "";
        }
    }

    public static final String getCveJsonDataOfCVEsFixedInZulu() {
        final String html      = getTextFromUrl(Constants.ZULU_CVE_URL, Charset.forName("UTF-8"));
        final int    jsonStart = html.indexOf("[ {");
        final int    jsonStop  = html.lastIndexOf("} ]") + 3;
        final String jsonTxt   = html.substring(jsonStart, jsonStop);
        return jsonTxt;
    }

    public static final Map<String, Set<VersionNumber>> getCVEsFixedInZulu() {
        final String html      = getTextFromUrl(Constants.ZULU_CVE_URL, Charset.forName("UTF-8"));
        final int    jsonStart = html.indexOf("[ {");
        final int    jsonStop  = html.lastIndexOf("} ]") + 3;
        final String jsonTxt   = html.substring(jsonStart, jsonStop);
        return getCVEsFixedInZulu(jsonTxt);
    }
    public static final Map<String, Set<VersionNumber>> getCVEsFixedInZulu(final String jsonTxt) {
        if (null == jsonTxt || jsonTxt.isEmpty()) { return new HashMap<>(); }
        enum Type {
            CPU,
            PSU,
            NONE;

            public static Type fromText(final String text) {
                switch (text) {
                    case "cpu", "CPU" -> { return Type.CPU; }
                    case "psu", "PSU" -> { return Type.PSU; }
                    default           -> { return Type.NONE;}
                }
            }
        }
        record Release(int year, int month) {

            public Month getMonth() { return Month.of(month); }

            @Override public String toString() { return new StringBuilder().append(year).append("_").append(month).toString(); }
        };
        record ZuluVersion(VersionNumber zuluVersion, VersionNumber jdkVersion, Type type) {};
        record CVE(String id, double baseScore, List<ZuluVersion> zuluVersions) {};
        record Update(Release release, List<CVE> cves) {};

        final Gson      gson      = new Gson();
        final JsonArray jsonArray = gson.fromJson(jsonTxt, JsonArray.class);
        List<Update>    updates   = new ArrayList<>();
        for (JsonElement updateElement : jsonArray) {
            JsonObject updateObj    = updateElement.getAsJsonObject();
            String[]   releaseParts = updateObj.get("release").getAsString().split("_");
            Release    release      = new Release(Integer.parseInt(releaseParts[0]), Integer.parseInt(releaseParts[1]));
            JsonArray  cvesArray    = updateObj.get("cves").getAsJsonArray();
            List<CVE>  cves         = new ArrayList<>();
            for (JsonElement cveElement : cvesArray) {
                JsonObject cveObj = cveElement.getAsJsonObject();
                String id        = cveObj.get("cve").getAsString();
                double baseScore = cveObj.get("baseScore").getAsDouble();
                JsonArray zuluVersionsArray = cveObj.get("zulu_versions").getAsJsonArray();
                List<ZuluVersion> zuluVersions = new ArrayList<>();
                for (JsonElement zuluVersionElement : zuluVersionsArray) {
                    JsonObject zuluVersionObj = zuluVersionElement.getAsJsonObject();
                    VersionNumber zuluVersion = VersionNumber.fromText(zuluVersionObj.get("zulu").getAsString());
                    VersionNumber jdkVersion  = VersionNumber.fromText(zuluVersionObj.get("jdk").getAsString());
                    Type          type        = zuluVersionObj.has("type") ? Type.fromText(zuluVersionObj.get("type").getAsString()) : Type.NONE;
                    zuluVersions.add(new ZuluVersion(zuluVersion, jdkVersion, type));
                }
                cves.add(new CVE(id, baseScore, zuluVersions));
            }
            updates.add(new Update(release, cves));
        }
        Map<String, Set<VersionNumber>> cveMap = new HashMap<>();
        updates.stream().forEach(update -> {
            update.cves.forEach(cve -> {
                if (!cveMap.containsKey(cve.id)) { cveMap.put(cve.id, new HashSet<>()); }
                cve.zuluVersions.forEach(zuluVersion -> {
                    cveMap.get(cve.id).add(zuluVersion.jdkVersion);
                });
            });
        });
        return cveMap;
    }

    public static final Map<VersionNumber, VersionNumber> getVersionZuluOpenJDKMap(final String jsonTxt) {
        if (null == jsonTxt || jsonTxt.isEmpty()) { return new HashMap<>(); }
        final Gson      gson      = new Gson();
        final JsonArray jsonArray = gson.fromJson(jsonTxt, JsonArray.class);
        Map<VersionNumber, VersionNumber> versionZuluOpenJDKMap = new HashMap<>();
        for (JsonElement updateElement : jsonArray) {
            JsonObject updateObj = updateElement.getAsJsonObject();
            JsonArray  cvesArray = updateObj.get("cves").getAsJsonArray();
            for (JsonElement cveElement : cvesArray) {
                JsonObject cveObj = cveElement.getAsJsonObject();
                JsonArray zuluVersionsArray = cveObj.get("zulu_versions").getAsJsonArray();
                for (JsonElement zuluVersionElement : zuluVersionsArray) {
                    JsonObject zuluVersionObj = zuluVersionElement.getAsJsonObject();
                    VersionNumber zuluVersion = VersionNumber.fromText(zuluVersionObj.get("zulu").getAsString());
                    VersionNumber jdkVersion  = VersionNumber.fromText(zuluVersionObj.get("jdk").getAsString());
                    versionZuluOpenJDKMap.put(zuluVersion, jdkVersion);
                }
            }
        }
        return versionZuluOpenJDKMap;
    }

    public static final String urlEncode(final String text) {
        try {
            return URLEncoder.encode(text, StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static String readTextFile(final String filename) throws IOException {
        final Path           path    = Paths.get(filename);
        final BufferedReader reader  = Files.newBufferedReader(path);
        final StringBuilder  builder = new StringBuilder();
        reader.lines().forEach(line -> builder.append(line).append("\n"));
        return builder.toString();
    }

    public static final void saveToTextFileToUserFolder(final String filename, final String text) {
        if (null == text || text.isEmpty()) { return; }

        final File existingFile = new File(filename);
        if (existingFile.exists()) { existingFile.delete(); }

        try {
            Files.write(Paths.get(Constants.HOME_FOLDER + filename), text.getBytes());
        } catch (IOException e) {
            System.out.println("Error writing text file: " + filename);
        }
    }
}
