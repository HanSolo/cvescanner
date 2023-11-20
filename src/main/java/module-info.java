module eu.hansolo.cvescanner {
    requires java.base;
    requires java.net.http;

    requires transitive com.google.gson;
    requires transitive eu.hansolo.jdktools;

    exports eu.hansolo.cvescanner;
}