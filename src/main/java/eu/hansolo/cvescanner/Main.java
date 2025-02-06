package eu.hansolo.cvescanner;

import eu.hansolo.cvescanner.Constants.CVE;
import eu.hansolo.jdktools.util.OutputFormat;
import eu.hansolo.jdktools.versioning.VersionNumber;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;


public class Main {
    private ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

    private AtomicBoolean openJdkUpdated  = new AtomicBoolean(false);
    private AtomicBoolean graalvmUPdated  = new AtomicBoolean(false);
    private AtomicBoolean zuluUpdated     = new AtomicBoolean(false);
    private AtomicBoolean correttoUpdated = new AtomicBoolean(false);
    private CveScanner    cveScanner      = new CveScanner(24);

    public Main() {
        cveScanner.addCveEvtConsumer(e -> {
            switch(e.type()) {
                case UPDATED_OPENJDK        -> {
                    System.out.println("OpenJDK updated");
                    openJdkUpdated.set(true);
                }
                case UPDATED_GRAALVM        -> graalvmUPdated.set(true);
                case UPDATED_ZULU           -> zuluUpdated.set(true);
                case UPDATED_CORRETTO       -> correttoUpdated.set(true);
                case UPDATE_OPENJDK_FAILED  -> {
                    System.out.println("OpenJDK update failed -> retry in 5 min");
                    executor.schedule(() -> { cveScanner.updateCves(); }, 300, TimeUnit.SECONDS);
                }
                case UPDATE_GRAALVM_FAILED  -> executor.schedule(() -> { cveScanner.updateGraalVMCves(); }, 300, TimeUnit.SECONDS);
                case UPDATE_ZULU_FAILED     -> executor.schedule(() -> { cveScanner.updateZuluCves(); }, 300, TimeUnit.SECONDS);
                case UPDATE_CORRETTO_FAILED -> executor.schedule(() -> { cveScanner.updateCorrettoCves(); }, 300, TimeUnit.SECONDS);
                case ERROR                  -> System.out.println("Error getting CVEs");
            }
        });

        cveScanner.updateCves(false);
        //cveScanner.updateGraalVMCves(false);
        //cveScanner.updateZuluCves(false);
        //cveScanner.updateCorrettoCves(false);

        while(!openJdkUpdated.get()) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {}
        }

        VersionNumber versionNumberToCheck = new VersionNumber(17, 0, 3, 1);
        List<CVE>     cvesFound            = cveScanner.findCvesForVersion(versionNumberToCheck);
        System.out.println("CVE's found for OpenJDK version: " + versionNumberToCheck.toString(OutputFormat.FULL_COMPRESSED, true, true));
        cvesFound.forEach(cve -> System.out.println(cve));

        /*
        System.out.println();

        VersionNumber versionNumberToCheckInZulu = new VersionNumber(17, 0, 4, 0, 8);
        List<CVE>     cvesFoundInZulu            = cveScanner.findZuluCvesForVersion(versionNumberToCheckInZulu);
        System.out.println("CVE's found for Zulu version: " + versionNumberToCheckInZulu.toString(OutputFormat.FULL_COMPRESSED, true, true));
        cvesFoundInZulu.forEach(cve -> System.out.println(cve));
        */
    }


    public static void main(String[] args) {
        new Main();
    }
}
