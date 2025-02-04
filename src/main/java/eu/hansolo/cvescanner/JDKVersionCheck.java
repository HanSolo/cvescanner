package eu.hansolo.cvescanner;

import eu.hansolo.cvescanner.Constants.CVE;
import eu.hansolo.cvescanner.Constants.DistributionType;
import eu.hansolo.cvescanner.Constants.Severity;
import eu.hansolo.jdktools.util.OutputFormat;
import eu.hansolo.jdktools.versioning.VersionNumber;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;


public class JDKVersionCheck {
    AtomicBoolean openJdkUpdated = new AtomicBoolean(false);
    CveScanner    cveScanner     = new CveScanner(3);


    public JDKVersionCheck(final int majorVersion) {
        cveScanner.addCveEvtConsumer(e -> {
            switch(e.type()) {
                case UPDATED_OPENJDK -> openJdkUpdated.set(true);
                case ERROR           -> System.out.println("Error getting CVEs");
            }
        });
        cveScanner.updateCves(false);
        while(!openJdkUpdated.get()) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {}
        }

        Map<VersionNumber, Set<CVE>> cvesPerMajorVersion = cveScanner.findCvesForMajorVersion(DistributionType.OPENJDK, majorVersion);
        cvesPerMajorVersion.entrySet().stream().sorted(Map.Entry.comparingByKey())
                           .forEach(entry -> {
                               final VersionNumber version  = entry.getKey();
                               final Set<CVE>      cves     = entry.getValue();
                               final List<CVE>     critical = cves.stream().filter(cve -> cve.severity() == Severity.CRITICAL).toList();
                               final List<CVE>     high     = cves.stream().filter(cve -> cve.severity() == Severity.HIGH).toList();
                               final List<CVE>     medium   = cves.stream().filter(cve -> cve.severity() == Severity.MEDIUM).toList();
                               final List<CVE>     low      = cves.stream().filter(cve -> cve.severity() == Severity.LOW).toList();
                               System.out.println(version.toString(OutputFormat.REDUCED_COMPRESSED, true, false) + "  Critical: " + critical.size() + "  High: " + high.size() + "  Medium: " + medium.size() + "  Low: " + low.size());
                           });


    }



    public static void main(String[] args) { new JDKVersionCheck(8); }
}
