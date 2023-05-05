module eu.hansolo.cvescanner {
    requires java.base;
    requires java.net.http;

    requires transitive com.google.gson;

    exports eu.hansolo.cvescanner;
}