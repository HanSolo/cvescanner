package eu.hansolo.cvescanner;

import eu.hansolo.cvescanner.Constants.CVE;
import eu.hansolo.jdktools.util.OutputFormat;
import eu.hansolo.jdktools.versioning.VersionNumber;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;


public class Main {

    public static void main(String[] args) {
        AtomicBoolean running        = new AtomicBoolean(true);
        AtomicBoolean openJdkUpdated = new AtomicBoolean(false);
        AtomicBoolean graalvmUPdated = new AtomicBoolean(false);
        CveScanner    cveScanner     = new CveScanner(3);

        cveScanner.addCveEvtConsumer(e -> {
            switch(e.type()) {
                case UPDATED_OPENJDK -> openJdkUpdated.set(true);
                case UPDATED_GRAALVM -> graalvmUPdated.set(true);
                case ERROR           -> System.out.println("Error getting CVEs");
            }
        });

        cveScanner.updateCves(false);
        cveScanner.updateGraalVMCves(false);

        while(!openJdkUpdated.get() && !graalvmUPdated.get()) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {}
        }

        VersionNumber versionNumberToCheck = new VersionNumber(17, 0, 3, 1);
        List<CVE>     cvesFound            = cveScanner.findCvesForVersion(versionNumberToCheck);
        System.out.println("CVE's found for OpenJDK version: " + versionNumberToCheck.toString(OutputFormat.FULL_COMPRESSED, true, true));
        cvesFound.forEach(cve -> System.out.println(cve));
    }
}
