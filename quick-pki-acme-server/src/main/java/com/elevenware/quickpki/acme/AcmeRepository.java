package com.elevenware.quickpki.acme;

import com.fasterxml.jackson.core.type.TypeReference;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

final class AcmeRepository {

    private static final TypeReference<List<Identifier>> IDENTIFIER_LIST = new TypeReference<>() {
    };

    private final DataSource dataSource;

    AcmeRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    Optional<CaMaterial> loadCaMaterial() {
        return queryOne("select issuer_info_json, certificate_pem, private_key_ciphertext, private_key_salt, private_key_iv from ca_material where id = ?",
                ps -> ps.setString(1, "default"),
                rs -> new CaMaterial(
                        rs.getString("issuer_info_json"),
                        rs.getString("certificate_pem"),
                        rs.getBytes("private_key_ciphertext"),
                        rs.getBytes("private_key_salt"),
                        rs.getBytes("private_key_iv")));
    }

    void saveCaMaterial(CaMaterial material) {
        update("insert into ca_material (id, issuer_info_json, certificate_pem, private_key_ciphertext, private_key_salt, private_key_iv) values (?, ?, ?, ?, ?, ?)",
                ps -> {
                    ps.setString(1, "default");
                    ps.setString(2, material.issuerInfoJson());
                    ps.setString(3, material.certificatePem());
                    ps.setBytes(4, material.privateKeyCiphertext());
                    ps.setBytes(5, material.privateKeySalt());
                    ps.setBytes(6, material.privateKeyIv());
                });
    }

    Optional<Account> findAccountByThumbprint(String thumbprint) {
        return queryOne("select * from acme_accounts where key_thumbprint = ?",
                ps -> ps.setString(1, thumbprint),
                this::account);
    }

    Optional<Account> findAccount(UUID id) {
        return queryOne("select * from acme_accounts where id = ?",
                ps -> ps.setObject(1, id),
                this::account);
    }

    Account createAccount(String thumbprint, String jwkJson, String contactJson, boolean termsAgreed) {
        UUID id = UUID.randomUUID();
        update("insert into acme_accounts (id, key_thumbprint, jwk_json, contact_json, status, terms_agreed) values (?, ?, ?, ?, ?, ?)",
                ps -> {
                    ps.setObject(1, id);
                    ps.setString(2, thumbprint);
                    ps.setString(3, jwkJson);
                    ps.setString(4, contactJson);
                    ps.setString(5, "valid");
                    ps.setBoolean(6, termsAgreed);
                });
        return new Account(id, thumbprint, jwkJson, contactJson, "valid", termsAgreed);
    }

    Order createOrder(Account account, List<Identifier> identifiers, AcmeConfig config) {
        UUID orderId = UUID.randomUUID();
        Instant expiresAt = Instant.now().plus(config.authzLifetime());
        String identifiersJson;
        try {
            identifiersJson = Json.MAPPER.writeValueAsString(identifiers);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize identifiers", e);
        }

        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement ps = connection.prepareStatement(
                        "insert into acme_orders (id, account_id, status, expires_at, identifiers_json) values (?, ?, ?, ?, ?)")) {
                    ps.setObject(1, orderId);
                    ps.setObject(2, account.id());
                    ps.setString(3, "pending");
                    ps.setTimestamp(4, Timestamp.from(expiresAt));
                    ps.setString(5, identifiersJson);
                    ps.executeUpdate();
                }
                for (Identifier identifier : identifiers) {
                    UUID authzId = UUID.randomUUID();
                    boolean wildcard = "dns".equals(identifier.type()) && identifier.value().startsWith("*.");
                    try (PreparedStatement ps = connection.prepareStatement(
                            "insert into acme_authorizations (id, order_id, identifier_type, identifier_value, wildcard, status, expires_at) values (?, ?, ?, ?, ?, ?, ?)")) {
                        ps.setObject(1, authzId);
                        ps.setObject(2, orderId);
                        ps.setString(3, identifier.type());
                        ps.setString(4, identifier.value());
                        ps.setBoolean(5, wildcard);
                        ps.setString(6, "pending");
                        ps.setTimestamp(7, Timestamp.from(expiresAt));
                        ps.executeUpdate();
                    }
                    if (!wildcard) {
                        insertChallenge(connection, authzId, "http-01");
                    }
                    insertChallenge(connection, authzId, "dns-01");
                }
                connection.commit();
            } catch (Exception e) {
                connection.rollback();
                throw e;
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create ACME order", e);
        }
        return loadOrder(orderId).orElseThrow();
    }

    Optional<Order> loadOrder(UUID id) {
        Optional<Order> order = queryOne("select * from acme_orders where id = ?",
                ps -> ps.setObject(1, id),
                rs -> new Order(
                        (UUID) rs.getObject("id"),
                        (UUID) rs.getObject("account_id"),
                        rs.getString("status"),
                        rs.getTimestamp("expires_at").toInstant(),
                        rs.getString("identifiers_json"),
                        rs.getBytes("csr_der"),
                        rs.getString("certificate_pem"),
                        rs.getString("chain_pem"),
                        List.of()));
        return order.map(o -> new Order(o.id(), o.accountId(), o.status(), o.expiresAt(), o.identifiersJson(),
                o.csrDer(), o.certificatePem(), o.chainPem(), loadAuthorizations(o.id())));
    }

    List<Order> loadOrdersForAccount(UUID accountId) {
        return queryMany("select * from acme_orders where account_id = ? order by created_at desc",
                ps -> ps.setObject(1, accountId),
                rs -> new Order(
                        (UUID) rs.getObject("id"),
                        (UUID) rs.getObject("account_id"),
                        rs.getString("status"),
                        rs.getTimestamp("expires_at").toInstant(),
                        rs.getString("identifiers_json"),
                        rs.getBytes("csr_der"),
                        rs.getString("certificate_pem"),
                        rs.getString("chain_pem"),
                        List.of()))
                .stream()
                .map(o -> new Order(o.id(), o.accountId(), o.status(), o.expiresAt(), o.identifiersJson(),
                        o.csrDer(), o.certificatePem(), o.chainPem(), loadAuthorizations(o.id())))
                .toList();
    }

    Optional<Authorization> loadAuthorization(UUID id) {
        Optional<Authorization> authz = queryOne("select * from acme_authorizations where id = ?",
                ps -> ps.setObject(1, id),
                this::authorization);
        return authz.map(a -> new Authorization(a.id(), a.orderId(), a.identifierType(), a.identifierValue(),
                a.wildcard(), a.status(), a.expiresAt(), loadChallenges(a.id())));
    }

    Optional<Challenge> loadChallenge(UUID id) {
        return queryOne("select * from acme_challenges where id = ?",
                ps -> ps.setObject(1, id),
                this::challenge);
    }

    Optional<Authorization> loadAuthorizationForChallenge(UUID challengeId) {
        return queryOne("""
                        select a.* from acme_authorizations a
                        join acme_challenges c on c.authorization_id = a.id
                        where c.id = ?
                        """,
                ps -> ps.setObject(1, challengeId),
                this::authorization)
                .map(a -> new Authorization(a.id(), a.orderId(), a.identifierType(), a.identifierValue(),
                        a.wildcard(), a.status(), a.expiresAt(), loadChallenges(a.id())));
    }

    void markChallengeValid(UUID challengeId) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                UUID authzId;
                UUID orderId;
                try (PreparedStatement ps = connection.prepareStatement(
                        "update acme_challenges set status = ?, validated_at = ? where id = ?")) {
                    ps.setString(1, "valid");
                    ps.setTimestamp(2, Timestamp.from(Instant.now()));
                    ps.setObject(3, challengeId);
                    ps.executeUpdate();
                }
                try (PreparedStatement ps = connection.prepareStatement(
                        "select authorization_id from acme_challenges where id = ?")) {
                    ps.setObject(1, challengeId);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (!rs.next()) {
                            throw new AcmeException(404, "malformed", "challenge not found");
                        }
                        authzId = (UUID) rs.getObject(1);
                    }
                }
                try (PreparedStatement ps = connection.prepareStatement(
                        "update acme_authorizations set status = ? where id = ? returning order_id")) {
                    ps.setString(1, "valid");
                    ps.setObject(2, authzId);
                    try (ResultSet rs = ps.executeQuery()) {
                        rs.next();
                        orderId = (UUID) rs.getObject(1);
                    }
                }
                if (allAuthorizationsValid(connection, orderId)) {
                    try (PreparedStatement ps = connection.prepareStatement(
                            "update acme_orders set status = ? where id = ? and status = ?")) {
                        ps.setString(1, "ready");
                        ps.setObject(2, orderId);
                        ps.setString(3, "pending");
                        ps.executeUpdate();
                    }
                }
                connection.commit();
            } catch (Exception e) {
                connection.rollback();
                throw e;
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to mark challenge valid", e);
        }
    }

    void markChallengeInvalid(UUID challengeId, String errorJson) {
        update("update acme_challenges set status = ?, error_json = ? where id = ?",
                ps -> {
                    ps.setString(1, "invalid");
                    ps.setString(2, errorJson);
                    ps.setObject(3, challengeId);
                });
    }

    void finalizeOrder(UUID orderId, byte[] csrDer, String certificatePem, String chainPem) {
        update("update acme_orders set status = ?, csr_der = ?, certificate_pem = ?, chain_pem = ? where id = ?",
                ps -> {
                    ps.setString(1, "valid");
                    ps.setBytes(2, csrDer);
                    ps.setString(3, certificatePem);
                    ps.setString(4, chainPem);
                    ps.setObject(5, orderId);
                });
    }

    List<Identifier> identifiers(Order order) {
        try {
            return Json.MAPPER.readValue(order.identifiersJson(), IDENTIFIER_LIST);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse order identifiers", e);
        }
    }

    private List<Authorization> loadAuthorizations(UUID orderId) {
        return queryMany("select * from acme_authorizations where order_id = ? order by id",
                ps -> ps.setObject(1, orderId),
                this::authorization)
                .stream()
                .map(a -> new Authorization(a.id(), a.orderId(), a.identifierType(), a.identifierValue(),
                        a.wildcard(), a.status(), a.expiresAt(), loadChallenges(a.id())))
                .toList();
    }

    private List<Challenge> loadChallenges(UUID authzId) {
        return queryMany("select * from acme_challenges where authorization_id = ? order by type",
                ps -> ps.setObject(1, authzId),
                this::challenge);
    }

    private void insertChallenge(Connection connection, UUID authzId, String type) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(
                "insert into acme_challenges (id, authorization_id, type, token, status) values (?, ?, ?, ?, ?)")) {
            ps.setObject(1, UUID.randomUUID());
            ps.setObject(2, authzId);
            ps.setString(3, type);
            ps.setString(4, Ids.randomUrlToken(32));
            ps.setString(5, "pending");
            ps.executeUpdate();
        }
    }

    private boolean allAuthorizationsValid(Connection connection, UUID orderId) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(
                "select count(*) from acme_authorizations where order_id = ? and status <> ?")) {
            ps.setObject(1, orderId);
            ps.setString(2, "valid");
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1) == 0;
            }
        }
    }

    private Account account(ResultSet rs) throws SQLException {
        return new Account((UUID) rs.getObject("id"), rs.getString("key_thumbprint"),
                rs.getString("jwk_json"), rs.getString("contact_json"),
                rs.getString("status"), rs.getBoolean("terms_agreed"));
    }

    private Authorization authorization(ResultSet rs) throws SQLException {
        return new Authorization((UUID) rs.getObject("id"), (UUID) rs.getObject("order_id"),
                rs.getString("identifier_type"), rs.getString("identifier_value"),
                rs.getBoolean("wildcard"), rs.getString("status"),
                rs.getTimestamp("expires_at").toInstant(), List.of());
    }

    private Challenge challenge(ResultSet rs) throws SQLException {
        Timestamp validatedAt = rs.getTimestamp("validated_at");
        return new Challenge((UUID) rs.getObject("id"), (UUID) rs.getObject("authorization_id"),
                rs.getString("type"), rs.getString("token"), rs.getString("status"),
                validatedAt == null ? null : validatedAt.toInstant(), rs.getString("error_json"));
    }

    private void update(String sql, StatementBinder binder) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            binder.bind(ps);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Database update failed", e);
        }
    }

    private <T> Optional<T> queryOne(String sql, StatementBinder binder, RowMapper<T> mapper) {
        List<T> results = queryMany(sql, binder, mapper);
        if (results.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(results.get(0));
    }

    private <T> List<T> queryMany(String sql, StatementBinder binder, RowMapper<T> mapper) {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            binder.bind(ps);
            try (ResultSet rs = ps.executeQuery()) {
                List<T> results = new ArrayList<>();
                while (rs.next()) {
                    results.add(mapper.map(rs));
                }
                return results;
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Database query failed", e);
        }
    }

    private interface StatementBinder {
        void bind(PreparedStatement ps) throws SQLException;
    }

    private interface RowMapper<T> {
        T map(ResultSet rs) throws SQLException;
    }
}
