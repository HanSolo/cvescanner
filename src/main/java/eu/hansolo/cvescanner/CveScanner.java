package eu.hansolo.cvescanner;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import eu.hansolo.jdktools.versioning.VersionNumber;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static eu.hansolo.cvescanner.Constants.*;


public class CveScanner {
    private static Logger               logger                      = LoggerFactory.getLogger(CveScanner.class);
    private final  Properties           PROPERTIES                  = PropertyManager.INSTANCE.getProperties();
    private final  CveEvt               UPDATED_OPENJDK             = new CveEvt(CveEvtType.UPDATED_OPENJDK);
    private final  CveEvt               UPDATED_GRAALVM             = new CveEvt(CveEvtType.UPDATED_GRAALVM);
    private final  CveEvt               UPDATED_ZULU                = new CveEvt(CveEvtType.UPDATED_ZULU);
    private final  CveEvt               UPDATED_CORRETTO            = new CveEvt(CveEvtType.UPDATED_CORRETTO);
    private final  CveEvt               UPDATE_OPENJDK_FAILED       = new CveEvt(CveEvtType.UPDATE_OPENJDK_FAILED);
    private final  CveEvt               UPDATE_GRAALVM_FAILED       = new CveEvt(CveEvtType.UPDATE_GRAALVM_FAILED);
    private final  CveEvt               UPDATE_ZULU_FAILED          = new CveEvt(CveEvtType.UPDATE_ZULU_FAILED);
    private final  CveEvt               UPDATE_CORRETTO_FAILED      = new CveEvt(CveEvtType.UPDATE_CORRETTO_FAILED);
    private final  CveEvt               OPEN_JDK_CVE_FILE_EMPTY     = new CveEvt(CveEvtType.OPENJDK_CVE_FILE_EMPTY);
    private final  CveEvt               GRAALVM_CVE_FILE_EMPTY      = new CveEvt(CveEvtType.GRAALVM_CVE_FILE_EMPTY);
    private final  CveEvt               ZULU_CVE_FILE_EMPTY         = new CveEvt(CveEvtType.ZULU_CVE_FILE_EMPTY);
    private final  CveEvt               CORRETTO_CVE_FILE_EMPTY     = new CveEvt(CveEvtType.CORRETTO_CVE_FILE_EMPTY);
    private final  CveEvt               UPDATE_OPENJDK_IN_PROGRESS  = new CveEvt(CveEvtType.UPDATE_OPENJDK_IN_PROGRESS);
    private final  CveEvt               UPDATE_GRAALVM_IN_PROGRESS  = new CveEvt(CveEvtType.UPDATE_GRAALVM_IN_PROGRESS);
    private final  CveEvt               UPDATE_ZULU_IN_PROGRESS     = new CveEvt(CveEvtType.UPDATE_ZULU_IN_PROGRESS);
    private final  CveEvt               UPDATE_CORRETTO_IN_PROGRESS = new CveEvt(CveEvtType.UPDATE_CORRETTO_IN_PROGRESS);
    private final  CveEvt               ERROR                       = new CveEvt(CveEvtType.ERROR);
    private final  List<CVE>            CVES                        = new CopyOnWriteArrayList<>();
    private final  List<CVE>            GRAALVM_CVES                = new CopyOnWriteArrayList<>();
    private final  List<CVE>            ZULU_CVES                   = new CopyOnWriteArrayList<>();
    private final  List<CVE>            CORRETTO_CVES               = new CopyOnWriteArrayList<>();
    private final  List<CveEvtConsumer> consumers                   = new CopyOnWriteArrayList<>();
    private final  AtomicBoolean        updateOpenJDKInProgress     = new AtomicBoolean(false);
    private final  AtomicBoolean        updateGraalVMInProgress     = new AtomicBoolean(false);
    private final  AtomicBoolean        updateZuluInProgress        = new AtomicBoolean(false);
    private final  AtomicBoolean        updateCorrettoInProgress    = new AtomicBoolean(false);
    private final  int                  updateInterval;
    private        HttpClient           httpClient;
    private        HttpClient           httpClientAsync;
    private        String               nvdApiKey;


    public CveScanner() {
        this("", 24);
    }
    public CveScanner(final int updateInterval) {
        this("", updateInterval);
    }
    public CveScanner(final String nvdApiKey, final int updateInterval) {
        if (updateInterval < MIN_UPDATE_INTERVAL_HOURS) {
            this.updateInterval = MIN_UPDATE_INTERVAL_HOURS;
        } else if (updateInterval > MAX_UPDATE_INTERVAL_HOURS) {
            this.updateInterval = MAX_UPDATE_INTERVAL_HOURS;
        } else {
            this.updateInterval = updateInterval;
        }
        this.nvdApiKey = null == nvdApiKey ? "" : nvdApiKey;
    }


    // ******************** Methods *******************************************
    public final String getNvdApiKey() { return nvdApiKey; }
    public final void setNvdApiKey(final String nvdApiKey) { this.nvdApiKey = null == nvdApiKey ? "" : nvdApiKey; }

    public final boolean updateCves() { return updateCves(false); }
    public final boolean updateCves(final boolean force) {
        if (this.updateOpenJDKInProgress.get()) {
            fireCveEvt(UPDATE_OPENJDK_IN_PROGRESS);
            return false;
        }
        // Update CVE's related to OpenJDK
        logger.debug("Updating OpenJDK CVEs");
        this.updateOpenJDKInProgress.set(true);
        final File cvedbOpenJDK = new File(CVE_DB_FILENAME);
        if (cvedbOpenJDK.exists()) {
            final Instant now = Instant.now();
            if (!force && Duration.between(Instant.ofEpochMilli(cvedbOpenJDK.lastModified()), now).toHours() < updateInterval) {
                this.updateOpenJDKInProgress.set(false);
                loadCvesFromFile();
                if (CVES.isEmpty()) {
                    logger.debug("Failed loading OpenJDK CVEs from file, file is empty");
                    cvedbOpenJDK.delete();
                    fireCveEvt(OPEN_JDK_CVE_FILE_EMPTY);
                    return false;
                } else {
                    logger.debug("Successfully loaded OpenJDK CVEs from file");
                    fireCveEvt(UPDATED_OPENJDK);
                    return true;
                }
            } else {
                final List<CVE> latestCVEs = getLatestCves(DistributionType.OPENJDK);
                if (latestCVEs.isEmpty()) {
                    // List of fetched CVEs is empty -> keep existing and retry later
                    logger.debug("Failed to update OpenJDK CVEs");
                    this.updateOpenJDKInProgress.set(false);
                    fireCveEvt(UPDATE_OPENJDK_FAILED);
                    return false;
                } else if (latestCVEs.size() < CVES.size()) {
                    // Number of fetched CVEs is smaller than existing number of CVEs -> keep existing and retry later
                    logger.debug("Failed to update OpenJDK CVEs");
                    this.updateOpenJDKInProgress.set(false);
                    fireCveEvt(UPDATE_OPENJDK_FAILED);
                    return false;
                } else {
                    // Upsert CVES
                    latestCVEs.forEach(cve -> {
                        if (CVES.contains(cve)) {
                            final Optional<CVE> optCve = CVES.stream().filter(existingCve -> existingCve.equals(cve)).findFirst();
                            if (optCve.isPresent()) {
                                final CVE existingCve = optCve.get();
                                for (VersionNumber versionNumber : cve.affectedVersions()) {
                                    if (!existingCve.affectedVersions().contains(versionNumber)) {
                                        existingCve.affectedVersions().add(versionNumber);
                                    }
                                }
                            }
                        } else {
                            CVES.add(cve);
                        }
                    });
                    cvedbOpenJDK.delete();
                    final StringBuilder jsonBuilder = new StringBuilder().append(CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
                    saveToJsonFile(CVE_DB_FILENAME, jsonBuilder.toString());
                    logger.debug("Successfully updated OpenJDK CVEs");
                    this.updateOpenJDKInProgress.set(false);
                    fireCveEvt(UPDATED_OPENJDK);
                    return true;
                }
            }
        } else {
            final List<CVE> latestCVEs = getLatestCves(DistributionType.OPENJDK);
            if (latestCVEs.isEmpty()) {
                // List of fetched CVEs is empty -> keep existing and retry later
                logger.debug("Failed to fetch OpenJDK CVEs");
                this.updateOpenJDKInProgress.set(false);
                fireCveEvt(OPEN_JDK_CVE_FILE_EMPTY);
                return false;
            } else {
                // Upsert CVES
                latestCVEs.forEach(cve -> {
                    if (CVES.contains(cve)) {
                        final Optional<CVE> optCve = CVES.stream().filter(existingCve -> existingCve.equals(cve)).findFirst();
                        if (optCve.isPresent()) {
                            final CVE existingCve = optCve.get();
                            for (VersionNumber versionNumber : cve.affectedVersions()) {
                                if (!existingCve.affectedVersions().contains(versionNumber)) {
                                    existingCve.affectedVersions().add(versionNumber);
                                }
                            }
                        }
                    } else {
                        CVES.add(cve);
                    }
                });
                final StringBuilder jsonBuilder = new StringBuilder().append(CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
                saveToJsonFile(CVE_DB_FILENAME, jsonBuilder.toString());
                logger.debug("Successfully updated OpenJDK CVEs");
                this.updateOpenJDKInProgress.set(false);
                fireCveEvt(UPDATED_OPENJDK);
                return true;
            }
        }
    }

    public final boolean updateGraalVMCves() {
        return updateGraalVMCves(false);
    }
    public final boolean updateGraalVMCves(final boolean force) {
        if (this.updateGraalVMInProgress.get()) {
            fireCveEvt(UPDATE_GRAALVM_IN_PROGRESS);
            return false;
        }
        // Update CVE's related to GraalVM
        logger.debug("Updating GraalVM CVEs");
        this.updateGraalVMInProgress.set(true);
        final File cvedbGraalVM = new File(CVE_DB_GRAALVM_FILENAME);
        if (cvedbGraalVM.exists()) {
            final Instant now = Instant.now();
            if (!force && Duration.between(Instant.ofEpochMilli(cvedbGraalVM.lastModified()), now).toHours() < updateInterval) {
                this.updateGraalVMInProgress.set(false);
                loadGraalVMCvesFromFile();
                if (GRAALVM_CVES.isEmpty()) {
                    logger.debug("Failed loading GraalVM CVEs from file, file is empty");
                    cvedbGraalVM.delete();
                    fireCveEvt(GRAALVM_CVE_FILE_EMPTY);
                    return false;
                } else {
                    logger.debug("Successfully loaded GraalVM CVEs from file");
                    fireCveEvt(UPDATED_GRAALVM);
                    return true;
                }
            } else {
                final List<CVE> latestCVEs = getLatestCves(DistributionType.GRAALVM);
                if (latestCVEs.isEmpty()) {
                    logger.debug("Failed to update GraalVM CVEs");
                    this.updateGraalVMInProgress.set(false);
                    fireCveEvt(UPDATE_GRAALVM_FAILED);
                    return false;
                } else if (latestCVEs.size() < GRAALVM_CVES.size()) {
                    logger.debug("Failed to update GraalVM CVEs");
                    this.updateGraalVMInProgress.set(false);
                    fireCveEvt(UPDATE_GRAALVM_FAILED);
                    return false;
                } else {
                    // Upsert GRAALVM_CVES
                    latestCVEs.forEach(cve -> {
                        if (GRAALVM_CVES.contains(cve)) {
                            final Optional<CVE> optCve = GRAALVM_CVES.stream().filter(existingCve -> existingCve.equals(cve)).findFirst();
                            if (optCve.isPresent()) {
                                final CVE existingCve = optCve.get();
                                for (VersionNumber versionNumber : cve.affectedVersions()) {
                                    if (!existingCve.affectedVersions().contains(versionNumber)) {
                                        existingCve.affectedVersions().add(versionNumber);
                                    }
                                }
                            }
                        } else {
                            GRAALVM_CVES.add(cve);
                        }
                    });
                    cvedbGraalVM.delete();
                    final StringBuilder jsonBuilder = new StringBuilder().append(GRAALVM_CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
                    saveToJsonFile(CVE_DB_GRAALVM_FILENAME, jsonBuilder.toString());
                    logger.debug("Successfully updated GraalVM CVEs");
                    this.updateGraalVMInProgress.set(false);
                    fireCveEvt(UPDATED_GRAALVM);
                    return true;
                }
            }
        } else {
            final List<CVE> latestCVEs = getLatestCves(DistributionType.GRAALVM);
            if (latestCVEs.isEmpty()) {
                logger.debug("Failed to fetch GraalVM CVEs");
                this.updateGraalVMInProgress.set(false);
                fireCveEvt(GRAALVM_CVE_FILE_EMPTY);
                return false;
            } else {
                latestCVEs.forEach(cve -> {
                    if (GRAALVM_CVES.contains(cve)) {
                        final Optional<CVE> optCve = GRAALVM_CVES.stream().filter(existingCve -> existingCve.equals(cve)).findFirst();
                        if (optCve.isPresent()) {
                            final CVE existingCve = optCve.get();
                            for (VersionNumber versionNumber : cve.affectedVersions()) {
                                if (!existingCve.affectedVersions().contains(versionNumber)) {
                                    existingCve.affectedVersions().add(versionNumber);
                                }
                            }
                        }
                    } else {
                        GRAALVM_CVES.add(cve);
                    }
                });
                final StringBuilder jsonBuilder = new StringBuilder().append(GRAALVM_CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
                saveToJsonFile(CVE_DB_GRAALVM_FILENAME, jsonBuilder.toString());
                logger.debug("Successfully updated GraalVM CVEs");
                this.updateGraalVMInProgress.set(false);
                fireCveEvt(UPDATED_GRAALVM);
                return true;
            }
        }
    }

    public final boolean updateZuluCves() {
        return updateZuluCves(false);
    }
    public final boolean updateZuluCves(final boolean force) {
        if (this.updateZuluInProgress.get()) {
            fireCveEvt(UPDATE_ZULU_IN_PROGRESS);
            return false;
        }
        // Update CVE's related to Zulu
        logger.debug("Updating Zulu CVEs");
        this.updateZuluInProgress.set(true);
        final File cvedbZulu = new File(CVE_DB_ZULU_FILENAME);
        if (cvedbZulu.exists()) {
            final Instant now = Instant.now();
            if (!force && Duration.between(Instant.ofEpochMilli(cvedbZulu.lastModified()), now).toHours() < updateInterval) {
                this.updateZuluInProgress.set(false);
                loadZuluCvesFromFile();
                if (ZULU_CVES.isEmpty()) {
                    logger.debug("Failed loading Zulu CVEs from file, file is empty");
                    cvedbZulu.delete();
                    fireCveEvt(ZULU_CVE_FILE_EMPTY);
                    return false;
                } else {
                    logger.debug("Successfully loaded Zulu CVEs from file");
                    fireCveEvt(UPDATED_ZULU);
                    return true;
                }
            } else {
                // Replace Zulu Versions with OpenJDK versions
                final Map<VersionNumber, VersionNumber> zuluVersions = Helper.getZuluVersions();
                final List<CVE>                         latestCves   = getLatestCves(DistributionType.ZULU);
                if (latestCves.isEmpty()) {
                    logger.debug("Failed to update Zulu CVEs");
                    this.updateZuluInProgress.set(false);
                    fireCveEvt(UPDATE_ZULU_FAILED);
                    return false;
                } else if (latestCves.size() < ZULU_CVES.size()) {
                    logger.debug("Failed to update Zulu CVEs");
                    this.updateZuluInProgress.set(false);
                    fireCveEvt(UPDATE_ZULU_FAILED);
                    return false;
                } else {
                    latestCves.forEach(cve -> {
                        List<VersionNumber> modifiedAffectedVersions = new ArrayList<>();
                        cve.affectedVersions().forEach(zuluVersion -> {
                            zuluVersions.entrySet().forEach(entry -> {
                                if (entry.getKey().getFeature().getAsInt() == zuluVersion.getFeature().getAsInt() && entry.getKey().getInterim().getAsInt() == zuluVersion.getInterim().getAsInt() &&
                                    entry.getKey().getUpdate().getAsInt() == zuluVersion.getUpdate().getAsInt() && entry.getKey().getPatch().getAsInt() == zuluVersion.getPatch().getAsInt()) {
                                    modifiedAffectedVersions.add(entry.getValue());
                                }
                            });
                        });
                        cve.affectedVersions().clear();
                        cve.affectedVersions().addAll(modifiedAffectedVersions);
                    });
                    // Upsert ZULU_CVES
                    latestCves.forEach(cve -> {
                        if (ZULU_CVES.contains(cve)) {
                            final Optional<CVE> optCve = ZULU_CVES.stream().filter(existingCve -> existingCve.equals(cve)).findFirst();
                            if (optCve.isPresent()) {
                                final CVE existingCve = optCve.get();
                                for (VersionNumber versionNumber : cve.affectedVersions()) {
                                    if (!existingCve.affectedVersions().contains(versionNumber)) {
                                        existingCve.affectedVersions().add(versionNumber);
                                    }
                                }
                            }
                        } else {
                            ZULU_CVES.add(cve);
                        }
                    });
                    cvedbZulu.delete();
                    final StringBuilder jsonBuilder = new StringBuilder().append(ZULU_CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
                    saveToJsonFile(CVE_DB_ZULU_FILENAME, jsonBuilder.toString());
                    logger.debug("Successfully updated Zulu CVEs");
                    this.updateZuluInProgress.set(false);
                    fireCveEvt(UPDATED_ZULU);
                    return true;
                }
            }
        } else {
            // Replace Zulu Versions with OpenJDK versions
            final Map<VersionNumber, VersionNumber> zuluVersions = Helper.getZuluVersions();
            final List<CVE>                         latestCves   = getLatestCves(DistributionType.ZULU);
            if (latestCves.isEmpty()) {
                logger.debug("Failed to fetch Zulu CVEs");
                this.updateZuluInProgress.set(false);
                fireCveEvt(ZULU_CVE_FILE_EMPTY);
                return false;
            } else {
                latestCves.forEach(cve -> {
                    List<VersionNumber> modifiedAffectedVersions = new ArrayList<>();
                    cve.affectedVersions().forEach(zuluVersion -> {
                        zuluVersions.entrySet().forEach(entry -> {
                            if (entry.getKey().getFeature().getAsInt() == zuluVersion.getFeature().getAsInt() && entry.getKey().getInterim().getAsInt() == zuluVersion.getInterim().getAsInt() &&
                                entry.getKey().getUpdate().getAsInt() == zuluVersion.getUpdate().getAsInt() && entry.getKey().getPatch().getAsInt() == zuluVersion.getPatch().getAsInt()) {
                                modifiedAffectedVersions.add(entry.getValue());
                            }
                        });
                    });
                    cve.affectedVersions().clear();
                    cve.affectedVersions().addAll(modifiedAffectedVersions);
                });
                // Upsert ZULU_CVES
                latestCves.forEach(cve -> {
                    if (ZULU_CVES.contains(cve)) {
                        final Optional<CVE> optCve = ZULU_CVES.stream().filter(existingCve -> existingCve.equals(cve)).findFirst();
                        if (optCve.isPresent()) {
                            final CVE existingCve = optCve.get();
                            for (VersionNumber versionNumber : cve.affectedVersions()) {
                                if (!existingCve.affectedVersions().contains(versionNumber)) {
                                    existingCve.affectedVersions().add(versionNumber);
                                }
                            }
                        }
                    } else {
                        ZULU_CVES.add(cve);
                    }
                });
                final StringBuilder jsonBuilder = new StringBuilder().append(ZULU_CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
                saveToJsonFile(CVE_DB_ZULU_FILENAME, jsonBuilder.toString());
                logger.debug("Successfully updated Zulu CVEs");
                this.updateZuluInProgress.set(false);
                fireCveEvt(UPDATED_ZULU);
                return true;
            }
        }
    }

    public final boolean updateCorrettoCves() {
        return updateCorrettoCves(false);
    }
    public final boolean updateCorrettoCves(final boolean force) {
        if (this.updateCorrettoInProgress.get()) {
            fireCveEvt(UPDATE_CORRETTO_IN_PROGRESS);
            return false;
        }
        // Update CVE's related to Corretto
        logger.debug("Updating Corretto CVEs");
        this.updateCorrettoInProgress.set(true);
        final File cvedbCorretto = new File(CVE_DB_CORRETTO_FILENAME);
        if (cvedbCorretto.exists()) {
            final Instant now = Instant.now();
            if (!force && Duration.between(Instant.ofEpochMilli(cvedbCorretto.lastModified()), now).toHours() < updateInterval) {
                this.updateCorrettoInProgress.set(false);
                loadCorrettoCvesFromFile();
                if (CORRETTO_CVES.isEmpty()) {
                    logger.debug("Failed loading Corretto CVEs from file, file is empty");
                    cvedbCorretto.delete();
                    fireCveEvt(CORRETTO_CVE_FILE_EMPTY);
                    return false;
                } else {
                    logger.debug("Successfully updated Corretto CVEs");
                    fireCveEvt(UPDATED_CORRETTO);
                    return true;
                }
            } else {
                final List<CVE> latestCves = getLatestCves(DistributionType.CORRETTO);
                if (latestCves.isEmpty()) {
                    logger.debug("Failed to update Corretto CVEs");
                    this.updateCorrettoInProgress.set(false);
                    fireCveEvt(UPDATE_CORRETTO_FAILED);
                    return false;
                } else if (latestCves.size() < CORRETTO_CVES.size()) {
                    logger.debug("Failed to update Corretto CVEs");
                    this.updateCorrettoInProgress.set(false);
                    fireCveEvt(UPDATE_CORRETTO_FAILED);
                    return false;
                } else {
                    // Upsert CORRETTO_CVES
                    latestCves.forEach(cve -> {
                        if (CORRETTO_CVES.contains(cve)) {
                            final Optional<CVE> optCve = CORRETTO_CVES.stream().filter(existingCve -> existingCve.equals(cve)).findFirst();
                            if (optCve.isPresent()) {
                                final CVE existingCve = optCve.get();
                                for (VersionNumber versionNumber : cve.affectedVersions()) {
                                    if (!existingCve.affectedVersions().contains(versionNumber)) {
                                        existingCve.affectedVersions().add(versionNumber);
                                    }
                                }
                            }
                        } else {
                            CORRETTO_CVES.add(cve);
                        }
                    });
                    cvedbCorretto.delete();
                    final StringBuilder jsonBuilder = new StringBuilder().append(CORRETTO_CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
                    saveToJsonFile(CVE_DB_CORRETTO_FILENAME, jsonBuilder.toString());
                    logger.debug("Successfully updated Corretto CVEs");
                    this.updateCorrettoInProgress.set(false);
                    fireCveEvt(UPDATED_CORRETTO);
                    return true;
                }
            }
        } else {
            final List<CVE> latestCves = getLatestCves(DistributionType.CORRETTO);
            if (latestCves.isEmpty()) {
                logger.debug("Failed to fetch Corretto CVEs");
                this.updateCorrettoInProgress.set(false);
                fireCveEvt(CORRETTO_CVE_FILE_EMPTY);
                return false;
            } else {
                // Upsert CORRETTO_CVES
                latestCves.forEach(cve -> {
                    if (CORRETTO_CVES.contains(cve)) {
                        final Optional<CVE> optCve = CORRETTO_CVES.stream().filter(existingCve -> existingCve.equals(cve)).findFirst();
                        if (optCve.isPresent()) {
                            final CVE existingCve = optCve.get();
                            for (VersionNumber versionNumber : cve.affectedVersions()) {
                                if (!existingCve.affectedVersions().contains(versionNumber)) {
                                    existingCve.affectedVersions().add(versionNumber);
                                }
                            }
                        }
                    } else {
                        CORRETTO_CVES.add(cve);
                    }
                });
                final StringBuilder jsonBuilder = new StringBuilder().append(ZULU_CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
                saveToJsonFile(CVE_DB_CORRETTO_FILENAME, jsonBuilder.toString());
                logger.debug("Successfully updated Corretto CVEs");
                this.updateCorrettoInProgress.set(false);
                fireCveEvt(UPDATED_CORRETTO);
                return true;
            }
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
    public final List<CVE> getZuluCves() {
        if (ZULU_CVES.isEmpty()) { updateZuluCves(); }
        return ZULU_CVES;
    }
    public final List<CVE> getCorrettoCves() {
        if (CORRETTO_CVES.isEmpty()) { updateCorrettoCves(); }
        return CORRETTO_CVES;
    }

    public final List<CVE> findCvesForVersion(final VersionNumber version) {
        return getCves().stream().filter(cve -> cve.affectedVersions().contains(version)).toList();
    }
    public final List<CVE> findGraalVMCvesForVersion(final VersionNumber version) {
        return getGraalVMCves().stream().filter(cve -> cve.affectedVersions().contains(version)).toList();
    }
    public final List<CVE> findZuluCvesForVersion(final VersionNumber version) {
        return getZuluCves().stream().filter(cve -> cve.affectedVersions().contains(version)).toList();
    }
    public final List<CVE> findCorrettoCvesForVersion(final VersionNumber version) { return getCorrettoCves().stream().filter(cve -> cve.affectedVersions().contains(version)).toList(); }

    public final Map<VersionNumber, Set<CVE>> findCvesForMajorVersion(final DistributionType distributionType, final int majorVersion) {
        final Map<VersionNumber, Set<CVE>> cvesPerVersionMap = new HashMap<>();
        final List<CVE> cvesToCheck;
        switch (distributionType) {
            case OPENJDK  -> cvesToCheck = getCves();
            case CORRETTO -> cvesToCheck = getCorrettoCves();
            case ZULU     -> cvesToCheck = getZuluCves();
            case GRAALVM  -> cvesToCheck = getGraalVMCves();
            default       -> cvesToCheck = getCves();
        }
        if (cvesToCheck.isEmpty()) {
            logger.debug("No CVEs found for major version " + majorVersion + " in distribution " + distributionType.name());
        }
        cvesToCheck.forEach(cve -> cve.affectedVersions()
                                           .stream()
                                           .filter(versionNumber -> versionNumber.getFeature().getAsInt() == majorVersion)
                                           .forEach(versionNumber -> {
            if (!cvesPerVersionMap.containsKey(versionNumber)) { cvesPerVersionMap.put(versionNumber, new HashSet<>()); }
            cvesPerVersionMap.get(versionNumber).add(cve);
        }));
        return cvesPerVersionMap;
    }

    public final boolean isOpenJDKUpdateInProgress() { return this.updateOpenJDKInProgress.get(); }
    public final boolean isGraalVMUpdateInProgress() { return this.updateGraalVMInProgress.get(); }
    public final boolean isCorrettoUpdateInProgress() { return this.updateCorrettoInProgress.get(); }
    public final boolean isZuluUpdateInProgress() { return this.updateZuluInProgress.get(); }

    public final void setCVES(final List<CVE> cves) {
        this.CVES.clear();
        this.CVES.addAll(cves);
        final StringBuilder jsonBuilder = new StringBuilder().append(CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
        saveToJsonFile(CVE_DB_FILENAME, jsonBuilder.toString());
    }
    public final void setGraalVMCves(final List<CVE> cves) {
        this.GRAALVM_CVES.clear();
        this.GRAALVM_CVES.addAll(cves);
        final StringBuilder jsonBuilder = new StringBuilder().append(GRAALVM_CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
        saveToJsonFile(CVE_DB_GRAALVM_FILENAME, jsonBuilder.toString());
    }
    public final void setZuluCves(final List<CVE> cves) {
        this.ZULU_CVES.clear();
        this.ZULU_CVES.addAll(cves);
        final StringBuilder jsonBuilder = new StringBuilder().append(ZULU_CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
        saveToJsonFile(CVE_DB_ZULU_FILENAME, jsonBuilder.toString());
    }
    public final void setCorrettoCves(final List<CVE> cves) {
        this.CORRETTO_CVES.clear();
        this.CORRETTO_CVES.addAll(cves);
        final StringBuilder jsonBuilder = new StringBuilder().append(CORRETTO_CVES.stream().map(cve -> cve.toString()).collect(Collectors.joining(COMMA, SQUARE_BRACKET_OPEN, SQUARE_BRACKET_CLOSE)));
        saveToJsonFile(CVE_DB_CORRETTO_FILENAME, jsonBuilder.toString());
    }

    public final List<CVE> loadCvesFromJsonFile(final String filename) {
        final List<CVE> cvesFound = new ArrayList<>();
        try {
            final String jsonText = new String(Files.readAllBytes(Paths.get(filename)));
            Gson gson = new GsonBuilder().setLenient().create();
            if (null != jsonText || !jsonText.isEmpty()) {
                final JsonArray cveArray = gson.fromJson(jsonText, JsonArray.class);
                for (int i = 0 ; i < cveArray.size() ; i++) {
                    final JsonObject json = cveArray.get(i).getAsJsonObject();
                    if (!json.has(CVE.FIELD_CVSS)) {
                        updateCves(true);
                        return cvesFound;
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
        } catch (IOException e) {
            logger.warn("Failed to load cves from file {}. Error: {}", filename, e);
        }
        return cvesFound;
    }

    private List<CVE> getLatestCves(final Constants.DistributionType distributionType) {
        if (getNvdApiKey().isEmpty() && (null == PROPERTIES.get(PropertyManager.PROPERTY_NVD_API_KEY) || PROPERTIES.get(PropertyManager.PROPERTY_NVD_API_KEY).toString().isEmpty())) {
            throw new IllegalArgumentException("NVD API Key cannot be empty");
        }
        final Map<String, List<VersionNumber>> cveMap      = new HashMap<>();
        final Map<String, Double>              scoreMap    = new HashMap<>();
        final Map<String, Severity>            severityMap = new HashMap<>();
        final Map<String, CVSS>                cvssMap     = new HashMap<>();

        switch (distributionType) {
            case OPENJDK -> {
                final List<CVE> cvesOpenJDK = getLatestCves(NVD_URL_OPENJDK_V2, distributionType);
                final List<CVE> cvesJDK     = getLatestCves(NVD_URL_JDK_V2, distributionType);
                final List<CVE> cvesJRE     = getLatestCves(NVD_URL_JRE_V2, distributionType);
                final List<CVE> cvesJavaSE  = getLatestCves(NVD_URL_JAVASE_V2, distributionType);

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
            case GRAALVM -> {
                final List<CVE> cvesGraalVM       = getLatestCves(NVD_URL_GRAALVM_V2, distributionType);
                final List<CVE> cvesGraalVMForJDK = getLatestCves(NVD_URL_GRAALVM_FOR_JDK_V2, distributionType);

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
            }
            case ZULU   ->  {
                final List<CVE> cvesZulu = getLatestCves(NVD_URL_AZUL_ZULU_V2, distributionType);

                // Add cve's found affecting GraalVM to map
                cvesZulu.forEach(cve -> {
                    cveMap.put(cve.id(), cve.affectedVersions());
                    scoreMap.put(cve.id(), cve.score());
                    severityMap.put(cve.id(), cve.severity());
                    cvssMap.put(cve.id(), cve.cvss());
                });
            }
            default     ->  {

            }
        }

        return cveMap.entrySet()
                     .stream()
                     .map(entry -> new CVE(entry.getKey(), scoreMap.get(entry.getKey()), cvssMap.get(entry.getKey()), severityMap.get(entry.getKey()), entry.getValue()))
                     .collect(Collectors.toList()).stream().sorted(Comparator.comparing(CVE::id)).collect(Collectors.toList());
    }
    private List<CVE> getLatestCves(final String url, final Constants.DistributionType distributionType) {
        final String               nvdApiKey = getNvdApiKey().isEmpty() ? PropertyManager.INSTANCE.getString(PropertyManager.PROPERTY_NVD_API_KEY) : getNvdApiKey();
        final List<CVE>            cvesFound = new ArrayList<>();
        final HttpResponse<String> response  = get(url, Map.of("apiKey", nvdApiKey,
                                                               "delay", NVD_API_DELAY_MILLIS,
                                                               "Accept", "application/json"));
        if (null == response) {
            logger.warn("Couldn't get response from NVD API");
            return cvesFound;
        }
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
                                        //if (vulnerable && criteria.startsWith("cpe:2.3:a:oracle:")) {
                                        if (vulnerable) {
                                            String[] parts;

                                            switch (distributionType) {
                                                case OPENJDK -> {
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
                                                case GRAALVM -> {
                                                    if (criteria.startsWith("cpe:2.3:a:oracle:graalvm:")) {
                                                        parts = criteria.replace("cpe:2.3:a:oracle:graalvm:", "").split(":");
                                                    } else if (criteria.startsWith("cpe:2.3:a:oracle:graalvm_for_jdk:")) {
                                                        parts = criteria.replace("cpe:2.3:a:oracle:graalvm_for_jdk:", "").split(":");
                                                    } else {
                                                        parts = new String[] {};
                                                    }
                                                }
                                                case ZULU    -> {
                                                    if (criteria.startsWith("cpe:2.3:a:azul:zulu:")) {
                                                        parts = criteria.replace("cpe:2.3:a:azul:zulu:", "").split(":");
                                                    } else {
                                                        parts = new String[] {};
                                                    }
                                                }
                                                default      -> {
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
            logger.warn("Error parsing CVEs: {}", e);
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
    }

    private void loadZuluCvesFromFile() {
        final List<CVE> cvesFound = new ArrayList<>();
        try {
            final String jsonText = new String(Files.readAllBytes(Paths.get(CVE_DB_ZULU_FILENAME)));
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
        ZULU_CVES.clear();
        ZULU_CVES.addAll(cvesFound);
    }

    private void loadCorrettoCvesFromFile() {
        final List<CVE> cvesFound = new ArrayList<>();
        try {
            final String jsonText = new String(Files.readAllBytes(Paths.get(CVE_DB_CORRETTO_FILENAME)));
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
        CORRETTO_CVES.clear();
        CORRETTO_CVES.addAll(cvesFound);
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
                                               .timeout(Duration.ofSeconds(GET_REQUEST_TIMEOUT_SECONDS))
                                               .build();

        try {
            HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                return response;
            } else {
                // Problem with url request
                if (response.statusCode() == 404) {
                    logger.debug("NVD API status code 404 means the given NVD API key is probably wrong");
                } else {
                    logger.debug("Error NVD API status code: " + response.statusCode() + " for url: {}", uri);
                }
                return response;
            }
        } catch (CompletionException | InterruptedException | IOException e) {
            logger.debug("Error requesting NVD API: {}", e);
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
                                               .timeout(Duration.ofSeconds(GET_REQUEST_TIMEOUT_SECONDS))
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
