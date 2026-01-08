package eu.hansolo.cvescanner;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import eu.hansolo.jdktools.ArchiveType;
import eu.hansolo.jdktools.util.OutputFormat;
import eu.hansolo.jdktools.versioning.VersionNumber;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.time.Month;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletionException;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static eu.hansolo.cvescanner.Constants.CDN_URL;
import static eu.hansolo.jdktools.Constants.COMMA;
import static eu.hansolo.cvescanner.Constants.HOME_FOLDER;
import static eu.hansolo.cvescanner.Constants.HREF_FILE_MATCHER;
import static eu.hansolo.cvescanner.Constants.ZULU_VERSIONS_FILENAME;
import static eu.hansolo.cvescanner.Constants.ZULU_VERSIONS_HOME_FILENAME;
import static eu.hansolo.jdktools.Constants.NEW_LINE;


public class Helper {
    private static HttpClient httpClient;


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

    public static List<String> readTextFileToList(final String filename) throws IOException {
        final Path           path   = Paths.get(filename);
        final BufferedReader reader = Files.newBufferedReader(path);
        return reader.lines().collect(Collectors.toList());
    }

    public static final void saveToTextFileToUserFolder(final String filename, final String text) {
        if (null == text || text.isEmpty()) { return; }

        final File existingFile = new File(filename);
        if (existingFile.exists()) { existingFile.delete(); }

        try {
            Files.write(Paths.get(HOME_FOLDER + filename), text.getBytes());
        } catch (IOException e) {
            System.out.println("Error writing text file: " + filename);
        }
    }

    public static final Map<VersionNumber, VersionNumber> getZuluVersions() {
        Map<VersionNumber, VersionNumber> zuluVersions = new HashMap<>();
        final File zuluVersionsFile = new File(ZULU_VERSIONS_HOME_FILENAME);
        if (zuluVersionsFile.exists()) {
            final Instant now = Instant.now();
            if (Duration.between(Instant.ofEpochMilli(zuluVersionsFile.lastModified()), now).toDays() < 30) {
                System.out.println("zulu versions up to date -> load file");
                zuluVersions = getZuluVersionsFromFile();
            } else {
                System.out.println("zulu versions outdated -> update from CDN");
                zuluVersions = Helper.getZuluVersionsFromCDN();
            }
        } else {
            System.out.println("zulu versions not present -> load from CDN");
            zuluVersions = Helper.getZuluVersionsFromCDN();
        }
        return zuluVersions;
    }
    public static final Map<VersionNumber, VersionNumber> getZuluVersionsFromFile() {
        Map<VersionNumber, VersionNumber> zuluVersions = new HashMap<>();
        try {
            List<String> lines = Helper.readTextFileToList(ZULU_VERSIONS_HOME_FILENAME);
            lines.forEach(line -> {
                String[] parts = line.split(COMMA);
                if (parts.length > 1) {
                    zuluVersions.put(VersionNumber.fromText(parts[0]), VersionNumber.fromText(parts[1]));
                }
            });
        } catch (IOException e) {
            System.out.println("Error loading zulu versions from file");
            return zuluVersions;
        }
        return zuluVersions;
    }
    public static final Map<VersionNumber, VersionNumber> getZuluVersionsFromCDN() {
        Map<VersionNumber, VersionNumber> zuluVersions = new HashMap<>();
        try {
            final HttpResponse<String> response = Helper.get(CDN_URL);
            if (null == response) { return zuluVersions; }
            final String html = response.body();
            if (html.isEmpty()) { return zuluVersions; }

            final Pattern filenamePrefixVersion       = Pattern.compile("(zulu|zre|zulu-repo|zulurepo)((-|_)?)(\\d+)\\.(\\d+)(\\.|\\+)(\\d+)(\\.|_?)(\\d+)?(-|_)([0-9]+-)?((ca|ea)(-))?(hl-)?(fx-)?(cp[0-9]+-)?(jdk|jre)?");
            final Pattern filenamePrefixDistroVersion = Pattern.compile("(zulu|zre|zulu-repo|zulurepo)");
            final List<String> fileHrefs              = new ArrayList<>(Helper.getFileHrefsFromString(html));
            for (String href : fileHrefs) {
                String filename = Helper.getFilenameFromText(href);
                if (filename.contains("noarch")) { continue; }
                String        reducedToVersionFilename       = filename.startsWith("zulu1.") ? filename.replaceAll(filenamePrefixDistroVersion.pattern(), "") : filename.replaceAll(filenamePrefixVersion.pattern(), "");
                VersionNumber versionNumber                  = VersionNumber.fromText(reducedToVersionFilename);
                String        reducedToDistroVersionFilename = filename.startsWith("zulu1.") ? filename.replaceAll(filenamePrefixVersion.pattern(), "") : filename.replaceAll(filenamePrefixDistroVersion.pattern(), "");
                VersionNumber distroVersionNumber            = VersionNumber.fromText(reducedToDistroVersionFilename);
                if (!versionNumber.toString(OutputFormat.FULL, true, false).equals(distroVersionNumber.toString(OutputFormat.FULL, true, false))) {
                    if (distroVersionNumber.getFeature().getAsInt() > 6 && versionNumber.getUpdate().getAsInt() < 9999) {
                        zuluVersions.put(distroVersionNumber, versionNumber);
                    }
                }
            }
            // Save to txt file
            StringBuilder txtBuilder = new StringBuilder();
            zuluVersions.entrySet().forEach(entry -> txtBuilder.append(entry.getKey().toString(OutputFormat.FULL,true,false)).append(COMMA).append(entry.getValue().toString(OutputFormat.FULL, true, false)).append(NEW_LINE));
            File zuluVersionsFile = new File(ZULU_VERSIONS_HOME_FILENAME);
            if (zuluVersionsFile.exists()) { zuluVersionsFile.delete();}
            Helper.saveToTextFileToUserFolder(ZULU_VERSIONS_FILENAME, txtBuilder.toString());
        } catch (Exception e) {
            System.out.println("Error fetching packages from Zulu CDN. " + e.getMessage());
        }
        return zuluVersions;
    }
    private static final Set<String> getFileHrefsFromString(final String text) {
        Set<String> hrefsFound = new HashSet<>();
        HREF_FILE_MATCHER.reset(text);
        while (HREF_FILE_MATCHER.find()) {
            hrefsFound.add(HREF_FILE_MATCHER.group(1));
        }
        return hrefsFound;
    }
    private static final String getFilenameFromText(final String text) {
        ArchiveType archiveTypeFound = getFileEnding(text);
        if (ArchiveType.NONE == archiveTypeFound || ArchiveType.NOT_FOUND == archiveTypeFound) { return ""; }
        int    lastSlash = text.lastIndexOf("/") + 1;
        String fileName  = text.substring(lastSlash);
        return fileName;
    }
    private static final ArchiveType getFileEnding(final String fileName) {
        if (null == fileName || fileName.isEmpty()) { return ArchiveType.NONE; }
        for (ArchiveType archiveType : ArchiveType.values()) {
            for (String ending : archiveType.getFileEndings()) {
                if (fileName.endsWith(ending)) { return archiveType; }
            }
        }
        return ArchiveType.NONE;
    }


    // ******************** REST calls ****************************************
    public static HttpClient createHttpClient() {
        return HttpClient.newBuilder()
                         .connectTimeout(Duration.ofSeconds(20))
                         .followRedirects(Redirect.NORMAL)
                         .version(java.net.http.HttpClient.Version.HTTP_2)
                         .build();
    }

    public static final HttpResponse<String> get(final String uri) { return get(uri, ""); }
    public static final HttpResponse<String> get(final String uri, final String userAgent) {
        if (null == httpClient) { httpClient = createHttpClient(); }
        final String userAgentText = (null == userAgent || userAgent.isEmpty()) ? "DiscoClient V2" : "DiscoClient V2 (" + userAgent + ")";
        HttpRequest request = HttpRequest.newBuilder()
                                         .GET()
                                         .uri(URI.create(uri))
                                         .setHeader("Accept", "application/json")
                                         .setHeader("User-Agent", userAgentText)
                                         .timeout(Duration.ofSeconds(60))
                                         .build();
        try {
            HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                return response;
            } else {
                // Problem with url request
                return response;
            }
        } catch (CompletionException | InterruptedException | IOException e) {
            return null;
        }
    }
}
