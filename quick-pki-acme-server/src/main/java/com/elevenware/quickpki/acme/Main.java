package com.elevenware.quickpki.acme;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    private Main() {
    }

    public static void main(String[] args) throws Exception {
        AcmeConfig config = AcmeConfig.fromEnv();
        LOG.info("Starting Quick-PKI ACME server port={} externalUrl={} databaseUrl={} dnsServers={} certificateDays={} authzHours={}",
                config.port(),
                config.externalUrl(),
                config.databaseUrl(),
                config.dnsServers(),
                config.certificateLifetime().toDays(),
                config.authzLifetime().toHours());
        Database database = Database.open(config);
        database.migrate();

        AcmeRepository repository = new AcmeRepository(database.dataSource());
        CertificateAuthorityService caService = CertificateAuthorityService.loadOrCreate(config, repository);
        NonceService nonceService = new NonceService();
        AcmeJwsService jwsService = new AcmeJwsService(repository, nonceService);
        ChallengeValidationService challengeValidationService = new ChallengeValidationService(config);

        AcmeServer server = new AcmeServer(
                config,
                repository,
                caService,
                nonceService,
                jwsService,
                challengeValidationService
        );
        server.start();
    }
}
