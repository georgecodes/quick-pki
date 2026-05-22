package com.elevenware.quickpki.certapi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    private Main() {
    }

    public static void main(String[] args) throws Exception {
        CertApiConfig config = CertApiConfig.fromEnv();
        LOG.info("Starting Quick-PKI certificate issuance API port={} externalUrl={} databaseUrl={} introspectionUrl={} certificateDays={} requiredScope={}",
                config.port(),
                config.externalUrl(),
                config.databaseUrl(),
                config.introspectionUrl(),
                config.certificateLifetime().toDays(),
                config.requiredScope());

        Database database = Database.open(config);
        database.migrate();

        CertApiRepository repository = new CertApiRepository(database.dataSource());
        CertificateAuthorityService caService = CertificateAuthorityService.loadOrCreate(config, repository);
        TokenIntrospector introspector = TokenIntrospector.fromConfig(config);

        CertApiServer server = new CertApiServer(config, repository, caService, introspector);
        server.start();
    }
}
