package eu.hansolo.cvescanner;

import java.util.concurrent.atomic.AtomicBoolean;


public class Main {
    public static void main(String[] args) {
        AtomicBoolean running    = new AtomicBoolean(true);
        CveScanner    cveScanner = new CveScanner();
        cveScanner.addCveEvtConsumer(e -> {
            switch(e.type()) {
                case UPDATED -> System.out.println(cveScanner.getCves());
                case ERROR   -> System.out.println("Error getting CVEs");
            }
            running.set(false);
        });

        cveScanner.updateCves();
        while(running.get()) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {}
        }

    }
}
