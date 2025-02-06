module eu.hansolo.cvescanner {
    requires java.net.http;

    requires transitive com.google.gson;
    requires transitive eu.hansolo.jdktools;
    requires transitive java.logging;
    requires transitive ch.qos.logback.classic;
    requires transitive ch.qos.logback.core;
    requires transitive org.slf4j;

    exports eu.hansolo.cvescanner;
}