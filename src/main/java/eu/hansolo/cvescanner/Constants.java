package eu.hansolo.cvescanner;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;


public class Constants {
    public static final String NVD_URL_OPENJDK         = "https://services.nvd.nist.gov/rest/json/cves/1.0/?cpeMatchString=cpe:2.3:a:oracle:openjdk:*:*:*:*:*:*:*:*&resultsPerPage=2000&apiKey=9a4bd31c-f084-4353-b3e5-6f1cc219410c";
    public static final String NVD_URL_JDK             = "https://services.nvd.nist.gov/rest/json/cves/1.0/?cpeMatchString=cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*&resultsPerPage=2000&apiKey=9a4bd31c-f084-4353-b3e5-6f1cc219410c";
    public static final String NVD_URL_JRE             = "https://services.nvd.nist.gov/rest/json/cves/1.0/?cpeMatchString=cpe:2.3:a:oracle:jre:*:*:*:*:*:*:*:*&resultsPerPage=2000&apiKey=9a4bd31c-f084-4353-b3e5-6f1cc219410c";
    public static final String NVD_URL_JAVASE          = "https://services.nvd.nist.gov/rest/json/cves/1.0/?cpeMatchString=cpe:2.3:a:oracle:java_se:*:*:*:*:*:*:*:*&resultsPerPage=2000&apiKey=9a4bd31c-f084-4353-b3e5-6f1cc219410c";
    public static final String NVD_URL_GRAALVM         = "https://services.nvd.nist.gov/rest/json/cves/1.0/?cpeMatchString=cpe:2.3:a:oracle:graalvm:*:*:*:*:*:*:*:*&resultsPerPage=2000&apiKey=9a4bd31c-f084-4353-b3e5-6f1cc219410c";
    public static final String NVD_URL_GRAALVM_FOR_JDK = "https://services.nvd.nist.gov/rest/json/cves/1.0/?cpeMatchString=cpe:2.3:a:oracle:graalvm_for_jdk:*:*:*:*:*:*:*:*&resultsPerPage=2000&apiKey=9a4bd31c-f084-4353-b3e5-6f1cc219410c";
    public static final String NVD_URL_JAR             = "https://services.nvd.nist.gov/rest/json/cves/2.0/?virtualMatchString=cpe:2.3:a:*:$NAME:$VERSION:*:*:*:*:*:*:*&resultsPerPage=100&noRejected";
    public static final String CVE_BASE_URL            = "http://cve.mitre.org/cgi-bin/cvename.cgi?name=";
    public static final String HOME_FOLDER             = new StringBuilder(System.getProperty("user.home")).append(File.separator).toString();
    public static final String CVE_DB_FILENAME         = HOME_FOLDER + "cvedb.json";
    public static final String CVE_DB_GRAALVM_FILENAME = HOME_FOLDER + "graalvm_cvedb.json";
    public static final String SQUARE_BRACKET_OPEN     = "[";
    public static final String SQUARE_BRACKET_CLOSE    = "]";
    public static final String CURLY_BRACKET_OPEN      = "{";
    public static final String CURLY_BRACKET_CLOSE     = "}";
    public static final String QUOTES                  = "\"";
    public static final String COLON                   = ":";
    public static final String COMMA                   = ",";


    // ******************** Enums *********************************************
    public enum CveEvtType { UPDATED, ERROR }

    public enum CVSS {
        CVSSV2, CVSSV3, NOT_FOUND;

        public static CVSS fromText(final String text) {
            if (null == text) { return NOT_FOUND; }
            switch (text) {
                case "CVSSV2", "cvssV2", "cvssv2" -> { return CVSSV2; }
                case "CVSSV3", "cvssV3", "cvssv3" -> { return CVSSV3; }
                default                           -> { return NOT_FOUND; }
            }
        }
    }

    public enum SeverityName {
        NONE,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL,
        NOT_FOUND;
    }

    public enum Severity {
        LOW(SeverityName.LOW.name(), SeverityName.LOW.name().toLowerCase(), 0.0, 3.9, 0.1, 3.9, 2),
        MEDIUM(SeverityName.MEDIUM.name(), SeverityName.MEDIUM.name().toLowerCase(), 4.0, 6.9, 4.0, 6.9, 3),
        HIGH(SeverityName.HIGH.name(), SeverityName.HIGH.name().toLowerCase(), 7.0, 10.0, 7.0, 8.9, 4),
        CRITICAL(SeverityName.CRITICAL.name(), SeverityName.CRITICAL.name().toLowerCase(), 10.0, 10.0, 9.0, 10.0, 5),
        NONE("-", "", 0, 0, 0, 0, 1),
        NOT_FOUND("", "", 0, 0, 0, 0, 0);

        private final String  uiString;
        private final String  apiString;
        private final double  minScoreV2;
        private final double  maxScoreV2;
        private final double  minScoreV3;
        private final double  maxScoreV3;
        private final Integer order;


        Severity(final String uiString, final String apiString, final double minScoreV2, final double maxScoreV2, final double minScoreV3, final double maxScoreV3, final Integer order) {
            this.uiString   = uiString;
            this.apiString  = apiString;
            this.minScoreV2 = minScoreV2;
            this.maxScoreV2 = maxScoreV2;
            this.minScoreV3 = minScoreV3;
            this.maxScoreV3 = maxScoreV3;
            this.order      = order;
        }

        public double getMinScoreV2() { return minScoreV2; }
        public double getMaxScoreV2() { return maxScoreV2; }

        public double getMinScoreV3() { return minScoreV3; }
        public double getMaxScoreV3() { return maxScoreV3; }

        public int getOrder() { return order; }


        public String getUiString() { return uiString; }

        public String getApiString() { return apiString; }

        public Severity getDefault()  { return Severity.NONE; }

        public Severity getNotFound() { return Severity.NOT_FOUND; }

        public Severity[] getAll()    { return values(); }

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
                case "low", "LOW", "Low"                -> { return LOW; }
                case "medium", "MEDIUM", "Medium"       -> { return MEDIUM; }
                case "high", "HIGH", "High"             -> { return HIGH; }
                case "critical", "CRITICAL", "Critical" -> { return CRITICAL; }
                default                                 -> { return NOT_FOUND; }
            }
        }

        public static Severity fromScore(final double score, final CVSS cvss) {
            switch (cvss) {
                case CVSSV2 -> {
                    if (score >= 0 && score <= 3.9) {
                        return Severity.LOW;
                    } else if (score > 3.9 && score <= 6.9) {
                        return Severity.MEDIUM;
                    } else if (score > 6.9 && score <= 10.0) {
                        return Severity.HIGH;
                    } else {
                        return Severity.NOT_FOUND;
                    }
                }
                case CVSSV3 -> {
                    if (score <= 0) {
                        return Severity.NONE;
                    } else if (score > 0 && score <= 3.9) {
                        return Severity.LOW;
                    } else if (score > 3.9 && score <= 6.9) {
                        return Severity.MEDIUM;
                    } else if (score > 6.9 && score < 8.9) {
                        return Severity.HIGH;
                    } else if (score > 8.9 && score <= 10.0) {
                        return Severity.CRITICAL;
                    } else {
                        return Severity.NOT_FOUND;
                    }
                }
            }
            return Severity.NOT_FOUND;
        }

        public static List<Severity> getAsList() { return Arrays.asList(values()); }

        public int compareToSeverity(final Severity other) {
            return order.compareTo(other.order);
        }
    }


    // ******************** Records *******************************************
    public record CveEvt(CveEvtType type) {}

    public record CVE(String id, double score, CVSS cvss, Severity severity, List<String> affectedVersions) implements Comparable<CVE> {
        public static final String FIELD_ID                = "id";
        public static final String FIELD_SCORE             = "score";
        public static final String FIELD_CVSS              = "cvss";
        public static final String FIELD_SEVERITY          = "severity";
        public static final String FIELD_URL               = "url";
        public static final String FIELD_AFFECTED_VERSIONS = "affected_versions";

        public String url() { return CVE_BASE_URL + id; }

        @Override public String toString() {
            return new StringBuilder().append(CURLY_BRACKET_OPEN)
                                      .append(QUOTES).append(FIELD_ID).append(QUOTES).append(COLON).append(QUOTES).append(id).append(QUOTES).append(COMMA)
                                      .append(QUOTES).append(FIELD_SCORE).append(QUOTES).append(COLON).append(score).append(COMMA)
                                      .append(QUOTES).append(FIELD_CVSS).append(QUOTES).append(COLON).append(QUOTES).append(cvss.name()).append(QUOTES).append(COMMA)
                                      .append(QUOTES).append(FIELD_SEVERITY).append(QUOTES).append(COLON).append(QUOTES).append(severity.name()).append(QUOTES).append(COMMA)
                                      .append(QUOTES).append(FIELD_URL).append(QUOTES).append(COLON).append(QUOTES).append(url()).append(QUOTES).append(COMMA)
                                      .append(QUOTES).append(FIELD_AFFECTED_VERSIONS).append(QUOTES).append(COLON)
                                      .append(affectedVersions.stream().collect(Collectors.joining("\",\"", "[\"", "\"]")))
                                      //.append(affectedVersions.stream().map(version -> version.toString(OutputFormat.REDUCED_COMPRESSED, true, false)).collect(Collectors.joining("\",\"", "[\"", "\"]")))
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
}
