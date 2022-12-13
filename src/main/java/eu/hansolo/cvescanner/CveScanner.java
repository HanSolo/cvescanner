package eu.hansolo.cvescanner;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import java.util.stream.Stream;


public class CveScanner {
    private static final String               NVD_URL_OPENJDK         = "https://services.nvd.nist.gov/rest/json/cves/1.0/?cpeMatchString=cpe:2.3:a:oracle:openjdk:*:*:*:*:*:*:*:*&resultsPerPage=2000&apiKey=9a4bd31c-f084-4353-b3e5-6f1cc219410c";
    private static final String               NVD_URL_JDK             = "https://services.nvd.nist.gov/rest/json/cves/1.0/?cpeMatchString=cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*&resultsPerPage=2000&apiKey=9a4bd31c-f084-4353-b3e5-6f1cc219410c";
    private static final String               NVD_URL_JRE             = "https://services.nvd.nist.gov/rest/json/cves/1.0/?cpeMatchString=cpe:2.3:a:oracle:jre:*:*:*:*:*:*:*:*&resultsPerPage=2000&apiKey=9a4bd31c-f084-4353-b3e5-6f1cc219410c";
    private static final String               NVD_URL_JAVASE          = "https://services.nvd.nist.gov/rest/json/cves/1.0/?cpeMatchString=cpe:2.3:a:oracle:java_se:*:*:*:*:*:*:*:*&resultsPerPage=2000&apiKey=9a4bd31c-f084-4353-b3e5-6f1cc219410c";
    private static final String               NVD_URL_GRAALVM         = "https://services.nvd.nist.gov/rest/json/cves/1.0/?cpeMatchString=cpe:2.3:a:oracle:graalvm:*:*:*:*:*:*:*:*&resultsPerPage=2000&apiKey=9a4bd31c-f084-4353-b3e5-6f1cc219410c";
    private static final String               HOME_FOLDER             = new StringBuilder(System.getProperty("user.home")).append(File.separator).toString();
    public  static final String               CVE_DB_FILENAME         = HOME_FOLDER + "cvedb.json";
    public  static final String               CVE_DB_GRAALVM_FILENAME = HOME_FOLDER + "graalvm_cvedb.json";
    private static final String               SQUARE_BRACKET_OPEN     = "[";
    private static final String               SQUARE_BRACKET_CLOSE    = "]";
    private static final String               CURLY_BRACKET_OPEN      = "{";
    private static final String               CURLY_BRACKET_CLOSE     = "}";
    private static final String               QUOTES                  = "\"";
    private static final String               COLON                   = ":";
    private static final String               COMMA                   = ",";
    private final        CveEvt               UPDATED                 = new CveEvt(CveEvtType.UPDATED);
    private final        CveEvt               ERROR                   = new CveEvt(CveEvtType.ERROR);
    private final        List<CVE>            CVES                    = new CopyOnWriteArrayList<>();
    private final        List<CVE>            GRAALVM_CVES            = new CopyOnWriteArrayList<>();
    private final        List<CveEvtConsumer> consumers               = new CopyOnWriteArrayList<>();
    private final        int                  updateInterval;
    private              HttpClient           httpClient;
    private              HttpClient           httpClientAsync;

    public enum CveEvtType { UPDATED, ERROR }
    public enum Severity {
        LOW("LOW", "LOW", 0.1, 3.9, 2),
        MEDIUM("MEDIUM", "MEDIUM", 4.0, 6.9, 3),
        HIGH("HIGH", "HIGH", 7.0, 8.9, 4),
        CRITICAL("CRITICAL", "CRITICAL", 9.0, 10.0, 5),
        NONE("-", "", 0, 0, 1),
        NOT_FOUND("", "", 0, 0, 0);

        private final String  uiString;
        private final String  apiString;
        private final double  minScore;
        private final double  maxScore;
        private final Integer order;


        Severity(final String uiString, final String apiString, final double minScore, final double maxScore, final Integer order) {
            this.uiString  = uiString;
            this.apiString = apiString;
            this.minScore  = minScore;
            this.maxScore  = maxScore;
            this.order     = order;
        }

        public double getMinScore() { return minScore; }

        public double getMaxScore() { return maxScore; }

        public int getOrder() { return order; }


        public String getUiString() { return uiString; }

        public String getApiString() { return apiString; }

        public Severity getDefault() { return Severity.NONE; }

        public Severity getNotFound() { return Severity.NOT_FOUND; }

        public Severity[] getAll() { return values(); }

        @Override public String toString() {
            return new StringBuilder().append(CURLY_BRACKET_OPEN)
                                      .append(QUOTES).append("name").append(QUOTES).append(COLON).append(QUOTES).append(name()).append(QUOTES).append(COMMA)
                                      .append(QUOTES).append("ui_string").append(QUOTES).append(COLON).append(QUOTES).append(uiString).append(QUOTES).append(COMMA)
                                      .append(QUOTES).append("api_string").append(QUOTES).append(COLON).append(QUOTES).append(apiString).append(QUOTES)
                                      .append(CURLY_BRACKET_CLOSE)
                                      .toString();
        }

        public static Severity fromText(final String text) {
            if (null == text) { return NOT_FOUND; }
            switch (text) {
                case "low":
                case "LOW":
                case "Low":
                    return LOW;
                case "medium":
                case "MEDIUM":
                case "Medium":
                    return MEDIUM;
                case "high":
                case "HIGH":
                case "High":
                    return HIGH;
                case "critical":
                case "CRITICAL":
                case "Critical":
                    return CRITICAL;
                default:
                    return NOT_FOUND;
            }
        }

        public static List<Severity> getAsList() { return Arrays.asList(values()); }

        public int compareToSeverity(final Severity other) {
            return order.compareTo(other.order);
        }
    }

    public record CVE(String id, double score, Severity severity, List<String> affectedVersions) implements Comparable<CVE> {
        public static final String FIELD_ID                = "id";
        public static final String FIELD_SCORE             = "score";
        public static final String FIELD_SEVERITY          = "severity";
        public static final String FIELD_URL               = "url";
        public static final String FIELD_AFFECTED_VERSIONS = "affected_versions";

        @Override public String toString() {
            return new StringBuilder().append(CURLY_BRACKET_OPEN)
                                      .append(QUOTES).append(FIELD_ID).append(QUOTES).append(COLON).append(QUOTES).append(id).append(QUOTES).append(COMMA)
                                      .append(QUOTES).append(FIELD_SCORE).append(QUOTES).append(COLON).append(score).append(COMMA)
                                      .append(QUOTES).append(FIELD_SEVERITY).append(QUOTES).append(COLON).append(QUOTES).append(severity.name()).append(QUOTES).append(COMMA)
                                      .append(QUOTES).append(FIELD_URL).append(QUOTES).append(COLON).append(QUOTES).append("http://cve.mitre.org/cgi-bin/cvename.cgi?name=" + id).append(QUOTES).append(COMMA)
                                      .append(QUOTES).append(FIELD_AFFECTED_VERSIONS).append(QUOTES).append(COLON)
                                      .append(affectedVersions.stream().collect(Collectors.joining("\",\"", "[\"", "\"]")))
                                      .append(CURLY_BRACKET_CLOSE).toString();
        }

        @Override public boolean equals(final Object o) {
            if (this == o) { return true; }
            if (o == null || getClass() != o.getClass()) { return false; }
            CVE cve2 = (CVE) o;
            return Double.compare(cve2.score, score) == 0 && id.equals(cve2.id);
        }
        @Override public int hashCode() {
            return Objects.hash(id, score);
        }

        @Override public int compareTo(final CVE other) { return id.compareTo(other.id()); }
    }

    public record CveEvt(CveEvtType type) {}


    public CveScanner() {
        this(6);
    }
    public CveScanner(final int updateInterval) {
        if (updateInterval < 1) {
            this.updateInterval = 1;
        } else if (updateInterval > 24) {
            this.updateInterval = 24;
        } else {
            this.updateInterval = updateInterval;
        }
        updateCves();
        updateGraalVMCves();
    }


    // ******************** Methods *******************************************
    public final void updateCves() {
        // Update CVE's related to OpenJDK
        final File cvedbOpenJDK = new File(CVE_DB_FILENAME);
        if (cvedbOpenJDK.exists()) {
            final Instant now = Instant.now();
            if (Duration.between(Instant.ofEpochMilli(cvedbOpenJDK.lastModified()), now).toHours() < updateInterval) {
                loadCvesFromFile();
            } else {
                CVES.clear();
                CVES.addAll(getLatestCves(false));
                final StringBuilder jsonBuilder = new StringBuilder().append(CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
                saveToJsonFile(CVE_DB_FILENAME, jsonBuilder.toString());
                fireCveEvt(UPDATED);
            }
        } else {
            CVES.clear();
            CVES.addAll(getLatestCves(false));
            final StringBuilder jsonBuilder = new StringBuilder().append(CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
            saveToJsonFile(CVE_DB_FILENAME, jsonBuilder.toString());
            fireCveEvt(UPDATED);
        }
    }
    public final void updateGraalVMCves() {
        // Update CVE's related to GraalVM
        final File cvedbGraalVM = new File(CVE_DB_GRAALVM_FILENAME);
        if (cvedbGraalVM.exists()) {
            final Instant now = Instant.now();
            if (Duration.between(Instant.ofEpochMilli(cvedbGraalVM.lastModified()), now).toHours() < updateInterval) {
                loadGraalVMCvesFromFile();
            } else {
                GRAALVM_CVES.clear();
                GRAALVM_CVES.addAll(getLatestCves(true));
                final StringBuilder jsonBuilder = new StringBuilder().append(GRAALVM_CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
                saveToJsonFile(CVE_DB_GRAALVM_FILENAME, jsonBuilder.toString());
                fireCveEvt(UPDATED);
            }
        } else {
            GRAALVM_CVES.clear();
            GRAALVM_CVES.addAll(getLatestCves(true));
            final StringBuilder jsonBuilder = new StringBuilder().append(GRAALVM_CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
            saveToJsonFile(CVE_DB_GRAALVM_FILENAME, jsonBuilder.toString());
            fireCveEvt(UPDATED);
        }
    }

    public final List<CVE> getCves() {
        if (CVES.isEmpty()) { updateCves(); }
        return CVES;
    }
    public final List<CVE> getGraalVMCves() {
        if (GRAALVM_CVES.isEmpty()) { updateGraalVMCves(); }
        return GRAALVM_CVES;
    }

    private List<CVE> getLatestCves(final boolean graalVmOnly) {
        final List<CVE>                 cvesOpenJDK = getLatestCves(NVD_URL_OPENJDK, graalVmOnly);
        final List<CVE>                 cvesJDK     = getLatestCves(NVD_URL_JDK, graalVmOnly);
        final List<CVE>                 cvesJRE     = getLatestCves(NVD_URL_JRE, graalVmOnly);
        final List<CVE>                 cvesJavaSE  = getLatestCves(NVD_URL_JAVASE, graalVmOnly);
        final List<CVE>                 cvesGraalVM = getLatestCves(NVD_URL_GRAALVM, graalVmOnly);

        final Map<String, List<String>> cveMap      = new HashMap<>();
        final Map<String, Double>       scoreMap    = new HashMap<>();
        final Map<String, Severity>     severityMap = new HashMap<>();

        // Add cve's found affecting OpenJDK to map
        cvesOpenJDK.forEach(cve -> {
            cveMap.put(cve.id(), cve.affectedVersions());
            scoreMap.put(cve.id(), cve.score());
            severityMap.put(cve.id(), cve.severity());
        });

        // Merge cve's found affecting JDK's with map
        cvesJDK.forEach(cve -> {
            if (cveMap.containsKey(cve.id())) {
                List<String> combined = Stream.concat(cve.affectedVersions().stream(), cveMap.get(cve.id()).stream()).distinct().collect(Collectors.toList());
                cveMap.put(cve.id(), combined);
            } else {
                cveMap.put(cve.id(), cve.affectedVersions());
                scoreMap.put(cve.id(), cve.score());
                severityMap.put(cve.id(), cve.severity());
            }
        });

        // Merge cve's found affecting JRE's with map
        cvesJRE.forEach(cve -> {
            if (cveMap.containsKey(cve.id())) {
                List<String> combined = Stream.concat(cve.affectedVersions().stream(), cveMap.get(cve.id()).stream()).distinct().collect(Collectors.toList());
                cveMap.put(cve.id(), combined);
            } else {
                cveMap.put(cve.id(), cve.affectedVersions());
                scoreMap.put(cve.id(), cve.score());
                severityMap.put(cve.id(), cve.severity());
            }
        });

        // Merge cve's found affecting JavaSE with map
        cvesJavaSE.forEach(cve -> {
            if (cveMap.containsKey(cve.id())) {
                List<String> combined = Stream.concat(cve.affectedVersions().stream(), cveMap.get(cve.id()).stream()).distinct().collect(Collectors.toList());
                cveMap.put(cve.id(), combined);
            } else {
                cveMap.put(cve.id(), cve.affectedVersions());
                scoreMap.put(cve.id(), cve.score());
                severityMap.put(cve.id(), cve.severity());
            }
        });

        return cveMap.entrySet().stream().map(entry -> new CVE(entry.getKey(), scoreMap.get(entry.getKey()), severityMap.get(entry.getKey()), entry.getValue())).collect(Collectors.toList());
    }
    private List<CVE> getLatestCves(final String url, final boolean graalvmOnly) {
        final List<CVE>            cvesFound = new ArrayList<>();
        final HttpResponse<String> response  = get(url);
        if (null == response) { return cvesFound; }
        final String      bodyText = response.body();
        final Gson        gson     = new Gson();
        final JsonElement element  = gson.fromJson(bodyText, JsonElement.class);
        if (element instanceof JsonObject) {
            final JsonObject jsonObj     = element.getAsJsonObject();
            final JsonObject resultObj   = jsonObj.get("result").getAsJsonObject();
            final JsonArray  cveItemsArr = resultObj.get("CVE_Items").getAsJsonArray();
            for (int i = 0 ; i < cveItemsArr.size() ; i++) {
                final JsonObject cveItem        = cveItemsArr.get(i).getAsJsonObject();
                final JsonObject cveObj         = cveItem.get("cve").getAsJsonObject();
                final JsonObject cveMetaData    = cveObj.get("CVE_data_meta").getAsJsonObject();
                final String     id             = cveMetaData.get("ID").getAsString();
                final JsonObject configurations = cveItem.get("configurations").getAsJsonObject();
                final JsonArray  nodes          = configurations.get("nodes").getAsJsonArray();
                Map<String, List<String>> cpesFound = new HashMap<>();
                for (int j = 0 ; j < nodes.size() ; j++) {
                    JsonObject node = nodes.get(j).getAsJsonObject();
                    JsonArray  cpeMatch = node.get("cpe_match").getAsJsonArray();
                    for (int k = 0 ; k < cpeMatch.size() ; k++) {
                        JsonObject match      = cpeMatch.get(k).getAsJsonObject();
                        boolean    vulnerable = match.get("vulnerable").getAsBoolean();
                        String     cpe23Uri   = match.get("cpe23Uri").getAsString();
                        if (vulnerable && cpe23Uri.startsWith("cpe:2.3:a:oracle:")) {
                            String parts[];
                            if (graalvmOnly) {
                                if (cpe23Uri.startsWith("cpe:2.3:a:oracle:graalvm:")) {
                                    parts = cpe23Uri.replace("cpe:2.3:a:oracle:graalvm:", "").split(":");
                                } else {
                                    parts = new String[] {};
                                }
                            } else {
                                if (cpe23Uri.startsWith("cpe:2.3:a:oracle:openjdk:")) {
                                    parts = cpe23Uri.replace("cpe:2.3:a:oracle:openjdk:", "").split(":");
                                } else if (cpe23Uri.startsWith("cpe:2.3:a:oracle:jdk:")) {
                                    parts = cpe23Uri.replace("cpe:2.3:a:oracle:jdk:", "").split(":");
                                } else if (cpe23Uri.startsWith("cpe:2.3:a:oracle:jdk:")) {
                                    parts = cpe23Uri.replace("cpe:2.3:a:oracle:jre:", "").split(":");
                                } else if (cpe23Uri.startsWith("cpe:2.3:a:oracle:java_se:")) {
                                    parts = cpe23Uri.replace("cpe:2.3:a:oracle:java_se:", "").split(":");
                                } else {
                                    parts = new String[] {};
                                }
                            }
                            if (parts.length == 0) { continue; }

                            String version = parts[0];
                            if (version.equals("*")) { continue; }
                            if (parts[1].startsWith("update")) {
                                if (parts[1].startsWith("update_0")) {
                                    version += parts[1].replace("update_0", ".0.");
                                } else if (parts[1].startsWith("update_")) {
                                    version += parts[1].replace("update_", ".0.");
                                } else {
                                    version += parts[1].replace("update", ".0.");
                                }
                                if (!cpesFound.containsKey(id)) { cpesFound.put(id, new ArrayList<>()); }
                                version = version.replace("1.6", "6");
                                version = version.replace("1.7", "7");
                                version = version.replace("1.8", "8");
                                version = version.replace("1.9", "9");
                                version = version.replace(".0.0.", ".0.");
                                version = version.replace("_b", "+");

                                if (!cpesFound.get(id).contains(version)) { cpesFound.get(id).add(version); }
                            } else {
                                if (!cpesFound.containsKey(id)) { cpesFound.put(id, new ArrayList<>()); }
                                version = version.replace("1.6", "6");
                                version = version.replace("1.7", "7");
                                version = version.replace("1.8", "8");
                                version = version.replace("1.9", "9");
                                version = version.replace(".0.0", "");
                                version = version.replace("_b", "+");

                                if (!cpesFound.get(id).contains(version)) { cpesFound.get(id).add(version); }
                            }
                        }
                    }
                }
                final JsonObject impact = cveItem.get("impact").getAsJsonObject();
                double score = -1;
                Severity severity = Severity.NONE;
                if (impact.has("baseMetricV3")) {
                    final JsonObject baseMetricV3 = impact.get("baseMetricV3").getAsJsonObject();
                    score = baseMetricV3.get("impactScore").getAsDouble();

                    final JsonObject cvssV3 = baseMetricV3.get("cvssV3").getAsJsonObject();
                    severity = Severity.valueOf(cvssV3.get("baseSeverity").getAsString());
                }
                if (!cpesFound.isEmpty() && score > 0 && severity != Severity.NONE) {
                    List<String> versionsFound = new ArrayList<>();
                    cpesFound.values().forEach(versions -> versionsFound.addAll(versions));
                    cvesFound.add(new CVE(id, score, severity, versionsFound));
                }
            }
        }
        return cvesFound;
    }

    private void loadCvesFromFile() {
        final List<CVE> cvesFound = new ArrayList<>();
        try {
            final String jsonText = new String(Files.readAllBytes(Paths.get(CVE_DB_FILENAME)));
            Gson gson = new GsonBuilder().create();
            if (null != jsonText || !jsonText.isEmpty()) {
                final JsonArray cveArray = gson.fromJson(jsonText, JsonArray.class);
                for (int i = 0 ; i < cveArray.size() ; i++) {
                    final JsonObject json = cveArray.get(i).getAsJsonObject();
                    if (json.has(CVE.FIELD_ID)) {
                        final String    id       = json.get(CVE.FIELD_ID).getAsString();
                        final double    score    = json.get(CVE.FIELD_SCORE).getAsDouble();
                        final Severity  severity = Severity.fromText(json.get(CVE.FIELD_SEVERITY).getAsString());
                        final JsonArray versions = json.get(CVE.FIELD_AFFECTED_VERSIONS).getAsJsonArray();
                        final List<String> affectedVersions = new ArrayList<>();
                        for (int j = 0 ; j < versions.size() ; j++) {
                            affectedVersions.add(versions.get(j).getAsString());
                        }
                        cvesFound.add(new CVE(id, score, severity, affectedVersions));
                    }
                }
            }
        } catch (IOException e) { fireCveEvt(ERROR); }

        if (cvesFound.isEmpty()) { return; }
        CVES.clear();
        CVES.addAll(cvesFound);
        fireCveEvt(UPDATED);
    }

    private void loadGraalVMCvesFromFile() {
        final List<CVE> cvesFound = new ArrayList<>();
        try {
            final String jsonText = new String(Files.readAllBytes(Paths.get(CVE_DB_GRAALVM_FILENAME)));
            Gson gson = new GsonBuilder().create();
            if (null != jsonText || !jsonText.isEmpty()) {
                final JsonArray cveArray = gson.fromJson(jsonText, JsonArray.class);
                for (int i = 0 ; i < cveArray.size() ; i++) {
                    final JsonObject json = cveArray.get(i).getAsJsonObject();
                    if (json.has(CVE.FIELD_ID)) {
                        final String    id       = json.get(CVE.FIELD_ID).getAsString();
                        final double    score    = json.get(CVE.FIELD_SCORE).getAsDouble();
                        final Severity  severity = Severity.fromText(json.get(CVE.FIELD_SEVERITY).getAsString());
                        final JsonArray versions = json.get(CVE.FIELD_AFFECTED_VERSIONS).getAsJsonArray();
                        final List<String> affectedVersions = new ArrayList<>();
                        for (int j = 0 ; j < versions.size() ; j++) {
                            affectedVersions.add(versions.get(j).getAsString());
                        }
                        cvesFound.add(new CVE(id, score, severity, affectedVersions));
                    }
                }
            }
        } catch (IOException e) { fireCveEvt(ERROR); }

        if (cvesFound.isEmpty()) { return; }
        GRAALVM_CVES.clear();
        GRAALVM_CVES.addAll(cvesFound);
        fireCveEvt(UPDATED);
    }

    private void saveToJsonFile(final String filename, final String jsonText) {
        if (null == jsonText || jsonText.isEmpty()) { return; }
        try {
            Files.write(Paths.get(filename), jsonText.getBytes());
        } catch (IOException e) { fireCveEvt(ERROR); }
    }


    // ******************** REST calls ****************************************
    private HttpClient createHttpClient() {
        return HttpClient.newBuilder()
                         .connectTimeout(Duration.ofSeconds(20))
                         .version(Version.HTTP_2)
                         .followRedirects(Redirect.NORMAL)
                         //.executor(Executors.newFixedThreadPool(4))
                         .build();
    }

    private HttpResponse<String> get(final String uri) {
        return get(uri, new HashMap<>());
    }
    private HttpResponse<String> get(final String uri, final Map<String,String> headers) {
        if (null == httpClient) { httpClient = createHttpClient(); }

        List<String> requestHeaders = new LinkedList<>();
        requestHeaders.add("User-Agent");
        requestHeaders.add("CveScanner");
        headers.entrySet().forEach(entry -> {
            final String name  = entry.getKey();
            final String value = entry.getValue();
            if (null != name && !name.isEmpty() && null != value && !value.isEmpty()) {
                requestHeaders.add(name);
                requestHeaders.add(value);
            }
        });

        final HttpRequest request = HttpRequest.newBuilder()
                                               .GET()
                                               .uri(URI.create(uri))
                                               .headers(requestHeaders.toArray(new String[0]))
                                               .timeout(Duration.ofSeconds(10))
                                               .build();

        try {
            HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                return response;
            } else {
                // Problem with url request
                //System.out.println("Error executing get request " + uri);
                //System.out.println("Response (Status Code " + response.statusCode()  + ")  " + response.body());
                return response;
            }
        } catch (CompletionException | InterruptedException | IOException e) {
            //System.out.println("Error executing get request " + uri + " : " + e.getMessage());
            fireCveEvt(ERROR);
            return null;
        }
    }

    private CompletableFuture<HttpResponse<String>> getAsync(final String uri) {
        return getAsync(uri, new HashMap<>());
    }
    private CompletableFuture<HttpResponse<String>> getAsync(final String uri, final Map<String, String> headers) {
        if (null == httpClientAsync) { httpClientAsync = createHttpClient(); }

        List<String> requestHeaders = new LinkedList<>();
        requestHeaders.add("User-Agent");
        requestHeaders.add("DiscoAPI");
        headers.entrySet().forEach(entry -> {
            final String name  = entry.getKey();
            final String value = entry.getValue();
            if (null != name && !name.isEmpty() && null != value && !value.isEmpty()) {
                requestHeaders.add(name);
                requestHeaders.add(value);
            }
        });

        final HttpRequest request = HttpRequest.newBuilder()
                                               .GET()
                                               .uri(URI.create(uri))
                                               .headers(requestHeaders.toArray(new String[0]))
                                               .timeout(Duration.ofSeconds(10))
                                               .build();

        return httpClientAsync.sendAsync(request, BodyHandlers.ofString());
    }


    // ******************** EventHandling *************************************
    public void addCveEvtConsumer(final CveEvtConsumer consumer) { if (!consumers.contains(consumer)) { consumers.add(consumer); } }
    public void removeCveEvtConsumer(final CveEvtConsumer consumer) { if (consumers.contains(consumer)) { consumers.remove(consumer); } }
    public void removeAllConsumers() { consumers.clear(); }

    private void fireCveEvt(final CveEvt evt) { consumers.forEach(consumer -> consumer.onCveEvt(evt)); }


    // ******************** Inner Classes *************************************
    @FunctionalInterface
    public interface CveEvtConsumer {
        void onCveEvt(CveEvt evt);
    }
}
