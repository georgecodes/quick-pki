package com.elevenware.quickpki.certapi;

import com.elevenware.quickpki.CertInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.h2.jdbcx.JdbcDataSource;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

final class CertApiTestSupport {

    private CertApiTestSupport() {
    }

    static CertApiConfig config(String introspectionUrl, String requiredScope) {
        return new CertApiConfig(
                0,
                "http://cert-api.test",
                "jdbc:h2:mem:test",
                "quickpki",
                "quickpki",
                "change-this-development-password",
                Duration.ofDays(90),
                introspectionUrl,
                "test-client-id",
                "test-client-secret",
                requiredScope,
                Duration.ofSeconds(5));
    }

    static DataSource dataSource() throws SQLException {
        JdbcDataSource dataSource = new JdbcDataSource();
        dataSource.setURL("jdbc:h2:mem:" + UUID.randomUUID()
                + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1");
        dataSource.setUser("sa");
        try (Connection connection = dataSource.getConnection()) {
            createSchema(connection);
        }
        return dataSource;
    }

    /** Builds a signed PKCS#10 request and returns it base64-encoded (DER). */
    static String base64Csr(String commonName) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=" + commonName), keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = builder.build(signer);
        return Base64.getEncoder().encodeToString(csr.getEncoded());
    }

    static String base64BrsealCsr(String commonName) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("UID=OFBBR-12345678,C=BR,O=ICP-Brasil,"
                        + "OU=Example CA,OU=12345678000199,"
                        + "OU=Validacao por certificado digital,CN=" + commonName),
                keyPair.getPublic());
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName[] {
                        otherName("2.16.76.1.3.2", "Responsible Person"),
                        otherName("2.16.76.1.3.3", "12345678000199"),
                        otherName("2.16.76.1.3.4", "197001010000000000000"),
                        otherName("2.16.76.1.3.7", "123456789012")
                }));
        builder.addAttribute(
                org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                extGen.generate());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = builder.build(signer);
        return Base64.getEncoder().encodeToString(csr.getEncoded());
    }

    private static GeneralName otherName(String oid, String value) {
        return CertInfo.builder().otherName(oid, value).build()
                .getOtherSubjectAlternativeNames().get(0);
    }

    private static void createSchema(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("""
                    create table ca_material (
                        id varchar(64) primary key,
                        issuer_info_json text not null,
                        certificate_pem text not null,
                        private_key_ciphertext bytea not null,
                        private_key_salt bytea not null,
                        private_key_iv bytea not null,
                        created_at timestamp with time zone not null default now()
                    )
                    """);
            statement.execute("""
                    create table issued_certificates (
                        id uuid primary key,
                        serial_number varchar(128) not null,
                        subject_dn varchar(1024) not null,
                        certificate_pem text not null,
                        chain_pem text not null,
                        csr_pem text,
                        not_before timestamp with time zone not null,
                        not_after timestamp with time zone not null,
                        client_id varchar(256),
                        created_at timestamp with time zone not null
                    )
                    """);
        }
    }
}
