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
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static eu.hansolo.cvescanner.Constants.*;


public class CveScanner {
    private final CveEvt               UPDATED      = new CveEvt(CveEvtType.UPDATED);
    private final CveEvt               ERROR        = new CveEvt(CveEvtType.ERROR);
    private final List<CVE>            CVES         = new CopyOnWriteArrayList<>();
    private final List<CVE>            GRAALVM_CVES = new CopyOnWriteArrayList<>();
    private final List<CveEvtConsumer> consumers    = new CopyOnWriteArrayList<>();
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
        final List<CVE> cvesOpenJDK       = getLatestCves(NVD_URL_OPENJDK, graalVmOnly);
        final List<CVE> cvesJDK           = getLatestCves(NVD_URL_JDK, graalVmOnly);
        final List<CVE> cvesJRE           = getLatestCves(NVD_URL_JRE, graalVmOnly);
        final List<CVE> cvesJavaSE        = getLatestCves(NVD_URL_JAVASE, graalVmOnly);
        final List<CVE> cvesGraalVM       = getLatestCves(NVD_URL_GRAALVM, graalVmOnly);
        final List<CVE> cvesGraalVMForJDK = getLatestCves(NVD_URL_GRAALVM_FOR_JDK, graalVmOnly);

        final Map<String, List<String>> cveMap      = new HashMap<>();
        final Map<String, Double>       scoreMap    = new HashMap<>();
        final Map<String, Severity>     severityMap = new HashMap<>();
        final Map<String, CVSS>         cvssMap     = new HashMap<>();

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
                List<String> combined = Stream.concat(cve.affectedVersions().stream(), cveMap.get(cve.id()).stream()).distinct().collect(Collectors.toList());
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
                List<String> combined = Stream.concat(cve.affectedVersions().stream(), cveMap.get(cve.id()).stream()).distinct().collect(Collectors.toList());
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
                List<String> combined = Stream.concat(cve.affectedVersions().stream(), cveMap.get(cve.id()).stream()).distinct().collect(Collectors.toList());
                cveMap.put(cve.id(), combined);
            } else {
                cveMap.put(cve.id(), cve.affectedVersions());
                scoreMap.put(cve.id(), cve.score());
                severityMap.put(cve.id(), cve.severity());
                cvssMap.put(cve.id(), cve.cvss());
            }
        });

        // Merge cve's found affecting GraalVM for JDK with map
        cvesGraalVMForJDK.forEach(cve -> {
            if (cveMap.containsKey(cve.id())) {
                List<String> combined = Stream.concat(cve.affectedVersions().stream(), cveMap.get(cve.id()).stream()).distinct().collect(Collectors.toList());
                cveMap.put(cve.id(), combined);
            } else {
                cveMap.put(cve.id(), cve.affectedVersions());
                scoreMap.put(cve.id(), cve.score());
                severityMap.put(cve.id(), cve.severity());
                cvssMap.put(cve.id(), cve.cvss());
            }
        });

        return cveMap.entrySet().stream().map(entry -> new CVE(entry.getKey(), scoreMap.get(entry.getKey()), cvssMap.get(entry.getKey()), severityMap.get(entry.getKey()), entry.getValue())).collect(Collectors.toList());
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

                                if (!cpesFound.get(id).contains(version) && !version.equals("-")) { cpesFound.get(id).add(version); }
                            } else {
                                if (!cpesFound.containsKey(id)) { cpesFound.put(id, new ArrayList<>()); }
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
                final JsonObject impact = cveItem.get("impact").getAsJsonObject();
                double score = -1;
                Severity severity = Severity.NONE;
                CVSS     cvss     = CVSS.NOT_FOUND;
                if (impact.has("baseMetricV3")) {
                    final JsonObject baseMetricV3 = impact.get("baseMetricV3").getAsJsonObject();
                    final JsonObject cvssV3       = baseMetricV3.get("cvssV3").getAsJsonObject();
                    severity = Severity.fromText(cvssV3.get("baseSeverity").getAsString());
                    score    = cvssV3.get("baseScore").getAsDouble();
                    cvss     = CVSS.CVSSV3;
                } else if (impact.has("baseMetricV2")) {
                    final JsonObject baseMetricV2 = impact.get("baseMetricV2").getAsJsonObject();
                    final JsonObject cvssV2       = baseMetricV2.get("cvssV2").getAsJsonObject();
                    severity = Severity.fromText(baseMetricV2.get("severity").getAsString());
                    score    = cvssV2.get("baseScore").getAsDouble();
                    cvss     = CVSS.CVSSV2;
                }

                if (!cpesFound.isEmpty() && score > 0 && severity != Severity.NONE) {
                    List<String> versionsFound = new ArrayList<>();
                    cpesFound.values().forEach(versions -> versionsFound.addAll(versions));
                    cvesFound.add(new CVE(id, score, cvss, severity, versionsFound));
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
                        final List<String> affectedVersions = new ArrayList<>();
                        for (int j = 0 ; j < versions.size() ; j++) {
                            final String version = versions.get(j).getAsString();
                            if (!version.equals("-")) {
                                affectedVersions.add(version);
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
                        final List<String> affectedVersions = new ArrayList<>();
                        for (int j = 0 ; j < versions.size() ; j++) {
                            final String version = versions.get(j).getAsString();
                            if (!version.equals("-")) {
                                affectedVersions.add(version);
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
