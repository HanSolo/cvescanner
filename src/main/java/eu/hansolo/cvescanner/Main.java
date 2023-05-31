package eu.hansolo.cvescanner;

import java.util.concurrent.atomic.AtomicBoolean;


public class Main {

    public static void main(String[] args) {
        /*
        List<Jar> jarFiles = Helper.getUsersJars();
        jarFiles.forEach(jar -> System.out.println(jar));
        System.exit(0);
        */

        AtomicBoolean running    = new AtomicBoolean(true);
        CveScanner    cveScanner = new CveScanner(3);
        cveScanner.addCveEvtConsumer(e -> {
            switch(e.type()) {
                case UPDATED -> System.out.println(cveScanner.getCves());
                case ERROR   -> System.out.println("Error getting CVEs");
            }
            running.set(false);
        });

        cveScanner.updateCves(true);
        cveScanner.updateGraalVMCves(true);
        while(running.get()) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {}
        }

    }
}
