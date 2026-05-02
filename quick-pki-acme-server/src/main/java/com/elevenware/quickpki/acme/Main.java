package com.elevenware.quickpki.acme;

public final class Main {

    private Main() {
    }

    public static void main(String[] args) throws Exception {
        AcmeConfig config = AcmeConfig.fromEnv();
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
