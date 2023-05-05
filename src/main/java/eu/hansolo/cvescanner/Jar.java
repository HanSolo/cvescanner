package eu.hansolo.cvescanner;

import eu.hansolo.cvescanner.Constants.CVE;

import java.util.ArrayList;
import java.util.List;


public class Jar {
    private String    path;
    private String    filename;
    private String    version;
    private boolean   vulnerable;
    private List<CVE> cves;


    public Jar(final String path, final String filename, final String version) {
        this(path, filename, version, false, new ArrayList<>());
    }
    public Jar(final String path, final String filename, final String version, final boolean vulnerable, final List<CVE> cves) {
        this.path       = path;
        this.filename   = filename;
        this.version    = version;
        this.vulnerable = vulnerable;
        this.cves       = cves;
    }


    public String getPath() { return path; }
    public void setPath(final String path) { this.path = path; }

    public String getFilename() { return filename; }
    public void setFilename(final String filename) { this.filename = filename; }

    public String getVersion() { return version; }
    public void setVersion(final String version) { this.version = version; }

    public boolean isVulnerable() { return vulnerable; }
    public void setVulnerable(final boolean vulnerable) { this.vulnerable = vulnerable; }

    public List<CVE> getCves() { return new ArrayList<>(cves); }
    public void setCves(final List<CVE> cves) {
        this.cves.clear();
        this.cves.addAll(cves);
    }

    @Override public String toString() {
        StringBuilder msgBuilder = new StringBuilder();
        msgBuilder.append("{").append("\"path\":\"").append(this.path).append("\",")
                  .append("\"filename\":\"").append(this.filename).append("\",")
                  .append("\"version\":\"").append(this.version).append("\",")
                  .append("\"vulnerable\":").append(this.vulnerable).append(",")
                  .append("\"vulnerabilities\":[")
                  .append("]").append("}");
        return msgBuilder.toString();
    }
}
