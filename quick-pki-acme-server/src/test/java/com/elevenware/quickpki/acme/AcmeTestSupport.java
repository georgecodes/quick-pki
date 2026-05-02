package com.elevenware.quickpki.acme;

import org.h2.jdbcx.JdbcDataSource;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.UUID;

final class AcmeTestSupport {

    private AcmeTestSupport() {
    }

    static AcmeConfig config() {
        return new AcmeConfig(
                0,
                "http://acme.test",
                "jdbc:h2:mem:test",
                "quickpki",
                "quickpki",
                "test-admin-token",
                "change-this-development-password",
                Duration.ofDays(90),
                Duration.ofHours(1),
                Duration.ofMillis(10),
                1,
                java.util.List.of());
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
                    create table acme_accounts (
                        id uuid primary key,
                        key_thumbprint varchar(256) not null unique,
                        jwk_json text not null,
                        contact_json text,
                        status varchar(32) not null,
                        terms_agreed boolean not null default false,
                        created_at timestamp with time zone not null default now()
                    )
                    """);
            statement.execute("""
                    create table acme_orders (
                        id uuid primary key,
                        account_id uuid not null,
                        status varchar(32) not null,
                        expires_at timestamp with time zone not null,
                        not_before timestamp with time zone,
                        not_after timestamp with time zone,
                        identifiers_json text not null,
                        csr_der bytea,
                        certificate_pem text,
                        chain_pem text,
                        created_at timestamp with time zone not null default now()
                    )
                    """);
            statement.execute("""
                    create table acme_authorizations (
                        id uuid primary key,
                        order_id uuid not null,
                        identifier_type varchar(32) not null,
                        identifier_value varchar(512) not null,
                        wildcard boolean not null default false,
                        status varchar(32) not null,
                        expires_at timestamp with time zone not null
                    )
                    """);
            statement.execute("""
                    create table acme_challenges (
                        id uuid primary key,
                        authorization_id uuid not null,
                        type varchar(32) not null,
                        token varchar(256) not null,
                        status varchar(32) not null,
                        validated_at timestamp with time zone,
                        error_json text
                    )
                    """);
        }
    }
}
