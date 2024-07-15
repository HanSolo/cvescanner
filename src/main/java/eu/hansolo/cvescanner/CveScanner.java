package eu.hansolo.cvescanner;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import eu.hansolo.jdktools.versioning.VersionNumber;

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
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static eu.hansolo.cvescanner.Constants.*;


public class CveScanner {
    private final Properties           PROPERTIES      = PropertyManager.INSTANCE.getProperties();
    private final CveEvt               UPDATED_OPENJDK = new CveEvt(CveEvtType.UPDATED_OPENJDK);
    private final CveEvt               UPDATED_GRAALVM = new CveEvt(CveEvtType.UPDATED_GRAALVM);
    private final CveEvt               ERROR           = new CveEvt(CveEvtType.ERROR);
    private final List<CVE>            CVES            = new CopyOnWriteArrayList<>();
    private final List<CVE>            GRAALVM_CVES    = new CopyOnWriteArrayList<>();
    private final List<CveEvtConsumer> consumers       = new CopyOnWriteArrayList<>();
    private final int                  updateInterval;
    private       HttpClient           httpClient;
    private       HttpClient           httpClientAsync;


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
    public final void updateCves() { updateCves(false); }
    public final void updateCves(final boolean force) {
        // Update CVE's related to OpenJDK
        final File cvedbOpenJDK = new File(CVE_DB_FILENAME);
        if (cvedbOpenJDK.exists()) {
            final Instant now = Instant.now();
            if (!force && Duration.between(Instant.ofEpochMilli(cvedbOpenJDK.lastModified()), now).toHours() < updateInterval) {
                loadCvesFromFile();
            } else {
                CVES.clear();
                CVES.addAll(getLatestCves(false));
                cvedbOpenJDK.delete();
                final StringBuilder jsonBuilder = new StringBuilder().append(CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
                saveToJsonFile(CVE_DB_FILENAME, jsonBuilder.toString());
                fireCveEvt(UPDATED_OPENJDK);
            }
        } else {
            CVES.clear();
            CVES.addAll(getLatestCves(false));
            final StringBuilder jsonBuilder = new StringBuilder().append(CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
            saveToJsonFile(CVE_DB_FILENAME, jsonBuilder.toString());
            fireCveEvt(UPDATED_OPENJDK);
        }
    }
    public final void updateGraalVMCves() {
        updateGraalVMCves(false);
    }
    public final void updateGraalVMCves(final boolean force) {
        // Update CVE's related to GraalVM
        final File cvedbGraalVM = new File(CVE_DB_GRAALVM_FILENAME);
        if (!force && cvedbGraalVM.exists()) {
            final Instant now = Instant.now();
            if (Duration.between(Instant.ofEpochMilli(cvedbGraalVM.lastModified()), now).toHours() < updateInterval) {
                loadGraalVMCvesFromFile();
            } else {
                GRAALVM_CVES.clear();
                GRAALVM_CVES.addAll(getLatestCves(true));
                cvedbGraalVM.delete();
                final StringBuilder jsonBuilder = new StringBuilder().append(GRAALVM_CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
                saveToJsonFile(CVE_DB_GRAALVM_FILENAME, jsonBuilder.toString());
                fireCveEvt(UPDATED_GRAALVM);
            }
        } else {
            GRAALVM_CVES.clear();
            GRAALVM_CVES.addAll(getLatestCves(true));
            final StringBuilder jsonBuilder = new StringBuilder().append(GRAALVM_CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
            saveToJsonFile(CVE_DB_GRAALVM_FILENAME, jsonBuilder.toString());
            fireCveEvt(UPDATED_GRAALVM);
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

    public final List<CVE> findCvesForVersion(final VersionNumber version) {
        return getCves().stream().filter(cve -> cve.affectedVersions().contains(version)).toList();
    }
    public final List<CVE> findGraalVMCvesForVersion(final VersionNumber version) {
        return getGraalVMCves().stream().filter(cve -> cve.affectedVersions().contains(version)).toList();
    }

    private List<CVE> getLatestCves(final boolean graalVmOnly) {
        if (null == PROPERTIES.get(PropertyManager.PROPERTY_NVD_API_KEY) || PROPERTIES.get(PropertyManager.PROPERTY_NVD_API_KEY).toString().isEmpty()) {
            throw new IllegalArgumentException("NVD API Key cannot be empty");
        }
        final Map<String, List<VersionNumber>> cveMap      = new HashMap<>();
        final Map<String, Double>              scoreMap    = new HashMap<>();
        final Map<String, Severity>            severityMap = new HashMap<>();
        final Map<String, CVSS>                cvssMap     = new HashMap<>();

        if (graalVmOnly) {
            final List<CVE> cvesGraalVM       = getLatestCves(NVD_URL_GRAALVM_V2, graalVmOnly);
            final List<CVE> cvesGraalVMForJDK = getLatestCves(NVD_URL_GRAALVM_FOR_JDK_V2, graalVmOnly);

            // Add cve's found affecting GraalVM to map
            cvesGraalVM.forEach(cve -> {
                cveMap.put(cve.id(), cve.affectedVersions());
                scoreMap.put(cve.id(), cve.score());
                severityMap.put(cve.id(), cve.severity());
                cvssMap.put(cve.id(), cve.cvss());
            });

            // Merge cve's found affecting GraalVM for JDK with map
            cvesGraalVMForJDK.forEach(cve -> {
                if (cveMap.containsKey(cve.id())) {
                    final List<VersionNumber> combined = Stream.concat(cve.affectedVersions().stream(), cveMap.get(cve.id()).stream()).distinct().collect(Collectors.toList());
                    cveMap.put(cve.id(), combined);
                } else {
                    cveMap.put(cve.id(), cve.affectedVersions());
                    scoreMap.put(cve.id(), cve.score());
                    severityMap.put(cve.id(), cve.severity());
                    cvssMap.put(cve.id(), cve.cvss());
                }
            });
        } else {
            final List<CVE> cvesOpenJDK = getLatestCves(NVD_URL_OPENJDK_V2, graalVmOnly);
            final List<CVE> cvesJDK     = getLatestCves(NVD_URL_JDK_V2, graalVmOnly);
            final List<CVE> cvesJRE     = getLatestCves(NVD_URL_JRE_V2, graalVmOnly);
            final List<CVE> cvesJavaSE  = getLatestCves(NVD_URL_JAVASE_V2, graalVmOnly);

            // Add cve's found affecting OpenJDK to map
            cvesOpenJDK.forEach(cve -> {
                cveMap.put(cve.id(), cve.affectedVersions());
                scoreMap.put(cve.id(), cve.score());
                severityMap.put(cve.id(), cve.severity());
                cvssMap.put(cve.id(), cve.cvss());
            });

            // Merge cve's found affecting JDK's with map
            cvesJDK.forEach(cve -> {
                if (cveMap.containsKey(cve.id())) {
                    final List<VersionNumber> combined = Stream.concat(cve.affectedVersions().stream(), cveMap.get(cve.id()).stream()).distinct().collect(Collectors.toList());
                    cveMap.put(cve.id(), combined);
                } else {
                    cveMap.put(cve.id(), cve.affectedVersions());
                    scoreMap.put(cve.id(), cve.score());
                    severityMap.put(cve.id(), cve.severity());
                    cvssMap.put(cve.id(), cve.cvss());
                }
            });

            // Merge cve's found affecting JRE's with map
            cvesJRE.forEach(cve -> {
                if (cveMap.containsKey(cve.id())) {
                    final List<VersionNumber> combined = Stream.concat(cve.affectedVersions().stream(), cveMap.get(cve.id()).stream()).distinct().collect(Collectors.toList());
                    cveMap.put(cve.id(), combined);
                } else {
                    cveMap.put(cve.id(), cve.affectedVersions());
                    scoreMap.put(cve.id(), cve.score());
                    severityMap.put(cve.id(), cve.severity());
                    cvssMap.put(cve.id(), cve.cvss());
                }
            });

            // Merge cve's found affecting JavaSE with map
            cvesJavaSE.forEach(cve -> {
                if (cveMap.containsKey(cve.id())) {
                    final List<VersionNumber> combined = Stream.concat(cve.affectedVersions().stream(), cveMap.get(cve.id()).stream()).distinct().collect(Collectors.toList());
                    cveMap.put(cve.id(), combined);
                } else {
                    cveMap.put(cve.id(), cve.affectedVersions());
                    scoreMap.put(cve.id(), cve.score());
                    severityMap.put(cve.id(), cve.severity());
                    cvssMap.put(cve.id(), cve.cvss());
                }
            });
        }

        return cveMap.entrySet()
                     .stream()
                     .map(entry -> new CVE(entry.getKey(), scoreMap.get(entry.getKey()), cvssMap.get(entry.getKey()), severityMap.get(entry.getKey()), entry.getValue()))
                     .collect(Collectors.toList()).stream().sorted(Comparator.comparing(CVE::id)).collect(Collectors.toList());
    }
    private List<CVE> getLatestCves(final String url, final boolean graalvmOnly) {
        final List<CVE>            cvesFound = new ArrayList<>();
        final HttpResponse<String> response  = get(url, Map.of("apiKey", PropertyManager.INSTANCE.getString(PropertyManager.PROPERTY_NVD_API_KEY),
                                                               "Accept", "application/json"));
        if (null == response) { return cvesFound; }
        final String bodyText = response.body();
        final Gson   gson     = new GsonBuilder().setLenient().create();
        try {
            final JsonElement element = gson.fromJson(bodyText, JsonElement.class);
            // ***** NVD API V2 *****
            if (element instanceof JsonObject) {
                        final JsonObject jsonObj         = element.getAsJsonObject();
                        final JsonArray  vulnerabilities = jsonObj.get("vulnerabilities").getAsJsonArray();
                        for (int i = 0 ; i < vulnerabilities.size() ; i++) {
                            final JsonObject cveItem     = vulnerabilities.get(i).getAsJsonObject();
                            final JsonObject cveObj      = cveItem.get("cve").getAsJsonObject();
                            final String     id          = cveObj.get("id").getAsString();
                            final JsonArray  configArray = cveObj.get("configurations").getAsJsonArray();
                            if (configArray.size() > 0) {
                                Map<String, List<String>> cpesFound = new HashMap<>();
                                for (int c = 0 ; c < configArray.size() ; c++) {
                                    final JsonObject configuration = configArray.get(c).getAsJsonObject();
                                    if (configuration.has("nodes")) {
                                        final JsonArray  nodesArray    = configuration.get("nodes").getAsJsonArray();
                                        for (int k = 0 ; k < nodesArray.size() ; k++) {
                                            JsonObject nodes = nodesArray.get(k).getAsJsonObject();
                                            JsonArray  cpeMatch = nodes.get("cpeMatch").getAsJsonArray();
                                            for (int l = 0 ; l < cpeMatch.size() ; l++) {
                                                JsonObject match      = cpeMatch.get(l).getAsJsonObject();
                                                boolean    vulnerable = match.get("vulnerable").getAsBoolean();
                                                String     criteria   = match.get("criteria").getAsString();
                                                if (vulnerable && criteria.startsWith("cpe:2.3:a:oracle:")) {
                                                    String[] parts;
                                                    if (graalvmOnly) {
                                                        if (criteria.startsWith("cpe:2.3:a:oracle:graalvm:")) {
                                                            parts = criteria.replace("cpe:2.3:a:oracle:graalvm:", "").split(":");
                                                        } else if (criteria.startsWith("cpe:2.3:a:oracle:graalvm_for_jdk:")) {
                                                            parts = criteria.replace("cpe:2.3:a:oracle:graalvm_for_jdk:", "").split(":");
                                                        } else {
                                                            parts = new String[] {};
                                                        }
                                                    } else {
                                                        if (criteria.startsWith("cpe:2.3:a:oracle:openjdk:")) {
                                                            parts = criteria.replace("cpe:2.3:a:oracle:openjdk:", "").split(":");
                                                        } else if (criteria.startsWith("cpe:2.3:a:oracle:jdk:")) {
                                                            parts = criteria.replace("cpe:2.3:a:oracle:jdk:", "").split(":");
                                                        } else if (criteria.startsWith("cpe:2.3:a:oracle:jre:")) {
                                                            parts = criteria.replace("cpe:2.3:a:oracle:jre:", "").split(":");
                                                        } else if (criteria.startsWith("cpe:2.3:a:oracle:java_se:")) {
                                                            parts = criteria.replace("cpe:2.3:a:oracle:java_se:", "").split(":");
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
                                                        version = version.replace("1.2", "2");
                                                        version = version.replace("1.3", "3");
                                                        version = version.replace("1.4", "4");
                                                        version = version.replace("1.5", "5");
                                                        version = version.replace("1.6", "6");
                                                        version = version.replace("1.7", "7");
                                                        version = version.replace("1.8", "8");
                                                        version = version.replace("1.9", "9");
                                                        version = version.replace(".0.0.", ".0.");
                                                        version = version.replace("_b", "+");

                                                        if (!cpesFound.get(id).contains(version) && !version.equals("-")) { cpesFound.get(id).add(version); }
                                                    } else {
                                                        if (!cpesFound.containsKey(id)) { cpesFound.put(id, new ArrayList<>()); }
                                                        version = version.replace("1.2", "2");
                                                        version = version.replace("1.3", "3");
                                                        version = version.replace("1.4", "4");
                                                        version = version.replace("1.5", "5");
                                                        version = version.replace("1.6", "6");
                                                        version = version.replace("1.7", "7");
                                                        version = version.replace("1.8", "8");
                                                        version = version.replace("1.9", "9");
                                                        version = version.replace(".0.0", "");
                                                        version = version.replace("_b", "+");

                                                        if (!cpesFound.get(id).contains(version) && !version.equals("-")) { cpesFound.get(id).add(version); }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                final JsonObject metrics = cveObj.get("metrics").getAsJsonObject();
                                double   scoreFound    = -1;
                                Severity severityFound = Severity.NONE;
                                CVSS     cvssFound     = CVSS.NOT_FOUND;
                                if (metrics.has(CVSS.CVSSV40.getMetricString())) {
                                    cvssFound = CVSS.CVSSV40;
                                    final JsonArray metricsArray = metrics.getAsJsonArray(CVSS.CVSSV40.getMetricString());
                                    if (metricsArray.size() > 0) {
                                        final JsonObject metricsObj  = metricsArray.get(0).getAsJsonObject();
                                        final JsonObject cvssDataObj = metricsObj.getAsJsonObject("cvssData");
                                        scoreFound    = cvssDataObj.get("baseScore").getAsDouble();
                                        severityFound = Severity.fromText(cvssDataObj.get("baseSeverity").getAsString());
                                    }
                                } else if (metrics.has(CVSS.CVSSV31.getMetricString())) {
                                    cvssFound = CVSS.CVSSV31;
                                    final JsonArray metricsArray = metrics.getAsJsonArray(CVSS.CVSSV31.getMetricString());
                                    if (metricsArray.size() > 0) {
                                        final JsonObject metricsObj  = metricsArray.get(0).getAsJsonObject();
                                        final JsonObject cvssDataObj = metricsObj.getAsJsonObject("cvssData");
                                        scoreFound    = cvssDataObj.get("baseScore").getAsDouble();
                                        severityFound = Severity.fromText(cvssDataObj.get("baseSeverity").getAsString());
                                    }
                                } else if (metrics.has(CVSS.CVSSV30.getMetricString())) {
                                    cvssFound = CVSS.CVSSV30;
                                    final JsonArray metricsArray = metrics.getAsJsonArray(CVSS.CVSSV30.getMetricString());
                                    if (metricsArray.size() > 0) {
                                        final JsonObject metricsObj  = metricsArray.get(0).getAsJsonObject();
                                        final JsonObject cvssDataObj = metricsObj.getAsJsonObject("cvssData");
                                        scoreFound    = cvssDataObj.get("baseScore").getAsDouble();
                                        severityFound = Severity.fromText(cvssDataObj.get("baseSeverity").getAsString());
                                    }
                                } else if (metrics.has(CVSS.CVSSV2.getMetricString())) {
                                    cvssFound = CVSS.CVSSV2;
                                    final JsonArray metricsArray = metrics.getAsJsonArray(CVSS.CVSSV2.getMetricString());
                                    if (metricsArray.size() > 0) {
                                        final JsonObject metricsObj  = metricsArray.get(0).getAsJsonObject();
                                        final JsonObject cvssDataObj = metricsObj.getAsJsonObject("cvssData");
                                        scoreFound    = cvssDataObj.get("baseScore").getAsDouble();
                                        severityFound = Severity.fromText(metricsObj.get("baseSeverity").getAsString());
                                    }
                                }

                                if (!cpesFound.isEmpty() && scoreFound > 0 && severityFound != Severity.NONE) {
                                    List<VersionNumber> versionsFound = new ArrayList<>();
                                    cpesFound.values().forEach(versions -> versions.forEach(version -> versionsFound.add(VersionNumber.fromText(version))));
                                    List<VersionNumber> sortedVersions = versionsFound.stream().sorted(Comparator.naturalOrder()).collect(Collectors.toList());
                                    cvesFound.add(new CVE(id, scoreFound, cvssFound, severityFound, sortedVersions));
                                }
                            }
                        }
                    }
        } catch (Exception e) {

        }
        return cvesFound;
    }

    private void loadCvesFromFile() {
        final List<CVE> cvesFound = new ArrayList<>();
        try {
            final String jsonText = new String(Files.readAllBytes(Paths.get(CVE_DB_FILENAME)));
            Gson gson = new GsonBuilder().setLenient().create();
            if (null != jsonText || !jsonText.isEmpty()) {
                final JsonArray cveArray = gson.fromJson(jsonText, JsonArray.class);
                for (int i = 0 ; i < cveArray.size() ; i++) {
                    final JsonObject json = cveArray.get(i).getAsJsonObject();
                    if (!json.has(CVE.FIELD_CVSS)) {
                        updateCves(true);
                        return;
                    }
                    if (json.has(CVE.FIELD_ID)) {
                        final String    id       = json.get(CVE.FIELD_ID).getAsString();
                        final double    score    = json.get(CVE.FIELD_SCORE).getAsDouble();
                        final CVSS      cvss     = CVSS.fromText(json.get(CVE.FIELD_CVSS).getAsString());
                        final Severity  severity = Severity.fromText(json.get(CVE.FIELD_SEVERITY).getAsString());
                        final JsonArray versions = json.get(CVE.FIELD_AFFECTED_VERSIONS).getAsJsonArray();
                        final List<VersionNumber> affectedVersions = new ArrayList<>();
                        for (int j = 0 ; j < versions.size() ; j++) {
                            final String version = versions.get(j).getAsString();
                            if (!version.equals("-")) {
                                affectedVersions.add(VersionNumber.fromText(version));
                            }
                        }
                        cvesFound.add(new CVE(id, score, cvss, severity, affectedVersions));
                    }
                }
            }
        } catch (IOException e) { fireCveEvt(ERROR); }

        if (cvesFound.isEmpty()) { return; }
        CVES.clear();
        CVES.addAll(cvesFound);
        fireCveEvt(UPDATED_OPENJDK);
    }

    private void loadGraalVMCvesFromFile() {
        final List<CVE> cvesFound = new ArrayList<>();
        try {
            final String jsonText = new String(Files.readAllBytes(Paths.get(CVE_DB_GRAALVM_FILENAME)));
            Gson gson = new GsonBuilder().setLenient().create();
            if (null != jsonText || !jsonText.isEmpty()) {
                final JsonArray cveArray = gson.fromJson(jsonText, JsonArray.class);
                for (int i = 0 ; i < cveArray.size() ; i++) {
                    final JsonObject json = cveArray.get(i).getAsJsonObject();
                    if (!json.has(CVE.FIELD_CVSS)) {
                        updateCves(true);
                        return;
                    }
                    if (json.has(CVE.FIELD_ID)) {
                        final String    id       = json.get(CVE.FIELD_ID).getAsString();
                        final double    score    = json.get(CVE.FIELD_SCORE).getAsDouble();
                        final CVSS      cvss     = CVSS.fromText(json.get(CVE.FIELD_CVSS).getAsString());
                        final Severity  severity = Severity.fromText(json.get(CVE.FIELD_SEVERITY).getAsString());
                        final JsonArray versions = json.get(CVE.FIELD_AFFECTED_VERSIONS).getAsJsonArray();
                        final List<VersionNumber> affectedVersions = new ArrayList<>();
                        for (int j = 0 ; j < versions.size() ; j++) {
                            final String version = versions.get(j).getAsString();
                            if (!version.equals("-")) {
                                affectedVersions.add(VersionNumber.fromText(version));
                            }
                        }
                        cvesFound.add(new CVE(id, score, cvss, severity, affectedVersions));
                    }
                }
            }
        } catch (IOException e) { fireCveEvt(ERROR); }

        if (cvesFound.isEmpty()) { return; }
        GRAALVM_CVES.clear();
        GRAALVM_CVES.addAll(cvesFound);
        fireCveEvt(UPDATED_GRAALVM);
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
                         .connectTimeout(Duration.ofSeconds(5))
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
                if (response.statusCode() == 404) {
                    System.out.println("NVD API status code 404 means the given NVD API key is probably wrong");
                } else {
                    System.out.println("Error NVD API status code: " + response.statusCode() + " for url: " + uri);
                }
                return response;
            }
        } catch (CompletionException | InterruptedException | IOException e) {
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
                                               .timeout(Duration.ofSeconds(5))
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
