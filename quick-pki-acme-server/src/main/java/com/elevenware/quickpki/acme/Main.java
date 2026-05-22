package com.elevenware.quickpki.acme;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    private Main() {
    }

    public static void main(String[] args) throws Exception {
        AcmeConfig config = AcmeConfig.fromEnv();
        LOG.info("Starting Quick-PKI ACME server port={} externalUrl={} databaseUrl={} dnsServers={} certificateDays={} authzHours={} issuance={} profile={}",
                config.port(),
                config.externalUrl(),
                config.databaseUrl(),
                config.dnsServers(),
                config.certificateLifetime().toDays(),
                config.authzLifetime().toHours(),
                config.remoteIssuer() == null ? "local-ca" : "remote-api",
                config.certificateProfile());
        Database database = Database.open(config);
        database.migrate();

        AcmeRepository repository = new AcmeRepository(database.dataSource());
        CertificateIssuer certificateIssuer = config.remoteIssuer() != null
                ? RemoteCertificateIssuer.fromConfig(config.remoteIssuer(), config.certificateProfile())
                : CertificateAuthorityService.loadOrCreate(config, repository);
        NonceService nonceService = new NonceService();
        AcmeJwsService jwsService = new AcmeJwsService(repository, nonceService);
        ChallengeValidationService challengeValidationService = new ChallengeValidationService(config);

        AcmeServer server = new AcmeServer(
                config,
                repository,
                certificateIssuer,
                nonceService,
                jwsService,
                challengeValidationService
        );
        server.start();
    }
}
