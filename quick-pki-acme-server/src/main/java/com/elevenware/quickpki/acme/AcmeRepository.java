package com.elevenware.quickpki.acme;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;

import javax.sql.DataSource;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;

final class AcmeRepository {

    private static final TypeReference<List<Identifier>> IDENTIFIER_LIST = new TypeReference<>() {
    };
    private static final String DEFAULT_CA_ID = "default";

    private final SqlSessionFactory sessionFactory;

    AcmeRepository(DataSource dataSource) {
        this.sessionFactory = MyBatis.sessionFactory(dataSource);
    }

    Optional<CaMaterial> loadCaMaterial() {
        return read(mapper -> Optional.ofNullable(mapper.selectCaMaterial(DEFAULT_CA_ID)));
    }

    void saveCaMaterial(CaMaterial material) {
        CaMaterialWrite row = new CaMaterialWrite(
                DEFAULT_CA_ID,
                material.issuerInfoJson(),
                material.certificatePem(),
                material.privateKeyCiphertext(),
                material.privateKeySalt(),
                material.privateKeyIv());
        write(mapper -> {
            if (mapper.updateCaMaterial(row) == 0) {
                mapper.insertCaMaterial(row);
            }
        });
    }

    Optional<Account> findAccountByThumbprint(String thumbprint) {
        return read(mapper -> Optional.ofNullable(mapper.selectAccountByThumbprint(thumbprint)));
    }

    Optional<Account> findAccount(UUID id) {
        return read(mapper -> Optional.ofNullable(mapper.selectAccount(id)));
    }

    Account createAccount(String thumbprint, String jwkJson, String contactJson, boolean termsAgreed) {
        Account account = new Account(UUID.randomUUID(), thumbprint, jwkJson, contactJson, "valid", termsAgreed);
        write(mapper -> mapper.insertAccount(account));
        return account;
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

        return transaction(mapper -> {
            mapper.insertOrder(new OrderWrite(orderId, account.id(), "pending", expiresAt, identifiersJson));
            for (Identifier identifier : identifiers) {
                UUID authzId = UUID.randomUUID();
                boolean wildcard = "dns".equals(identifier.type()) && identifier.value().startsWith("*.");
                mapper.insertAuthorization(new AuthorizationWrite(
                        authzId,
                        orderId,
                        identifier.type(),
                        identifier.value(),
                        wildcard,
                        "pending",
                        expiresAt));
                if (!wildcard) {
                    insertChallenge(mapper, authzId, "http-01");
                }
                insertChallenge(mapper, authzId, "dns-01");
            }
            return loadOrder(mapper, orderId).orElseThrow();
        }, "Failed to create ACME order");
    }

    Optional<Order> loadOrder(UUID id) {
        return read(mapper -> loadOrder(mapper, id));
    }

    List<Order> loadOrdersForAccount(UUID accountId) {
        return read(mapper -> mapper.selectOrdersForAccount(accountId)
                .stream()
                .map(row -> order(mapper, row))
                .toList());
    }

    Optional<Authorization> loadAuthorization(UUID id) {
        return read(mapper -> Optional.ofNullable(mapper.selectAuthorization(id))
                .map(row -> authorization(mapper, row)));
    }

    Optional<Challenge> loadChallenge(UUID id) {
        return read(mapper -> Optional.ofNullable(mapper.selectChallenge(id)));
    }

    Optional<Authorization> loadAuthorizationForChallenge(UUID challengeId) {
        return read(mapper -> Optional.ofNullable(mapper.selectAuthorizationForChallenge(challengeId))
                .map(row -> authorization(mapper, row)));
    }

    void markChallengeValid(UUID challengeId) {
        transaction(mapper -> {
            if (mapper.markChallengeValid(challengeId, Instant.now()) == 0) {
                throw new AcmeException(404, "malformed", "challenge not found");
            }
            UUID authzId = mapper.selectAuthorizationIdForChallenge(challengeId);
            if (authzId == null) {
                throw new AcmeException(404, "malformed", "challenge not found");
            }
            mapper.updateAuthorizationStatus(authzId, "valid");
            UUID orderId = mapper.selectOrderIdForAuthorization(authzId);
            if (mapper.countNonValidAuthorizations(orderId) == 0) {
                mapper.markOrderReadyIfPending(orderId);
            }
            return null;
        }, "Failed to mark challenge valid");
    }

    void markChallengeInvalid(UUID challengeId, String errorJson) {
        write(mapper -> mapper.markChallengeInvalid(challengeId, errorJson));
    }

    void finalizeOrder(UUID orderId, byte[] csrDer, String certificatePem, String chainPem) {
        write(mapper -> mapper.completeOrder(new OrderCompletion(orderId, "valid", csrDer, certificatePem, chainPem)));
    }

    List<Identifier> identifiers(Order order) {
        try {
            return Json.MAPPER.readValue(order.identifiersJson(), IDENTIFIER_LIST);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse order identifiers", e);
        }
    }

    private Optional<Order> loadOrder(AcmeMapper mapper, UUID id) {
        return Optional.ofNullable(mapper.selectOrder(id))
                .map(row -> order(mapper, row));
    }

    private Order order(AcmeMapper mapper, OrderRow row) {
        return row.toOrder(loadAuthorizations(mapper, row.id()));
    }

    private List<Authorization> loadAuthorizations(AcmeMapper mapper, UUID orderId) {
        return mapper.selectAuthorizationsForOrder(orderId)
                .stream()
                .map(row -> authorization(mapper, row))
                .toList();
    }

    private Authorization authorization(AcmeMapper mapper, AuthorizationRow row) {
        return row.toAuthorization(mapper.selectChallengesForAuthorization(row.id()));
    }

    private void insertChallenge(AcmeMapper mapper, UUID authzId, String type) {
        mapper.insertChallenge(new ChallengeWrite(UUID.randomUUID(), authzId, type, Ids.randomUrlToken(32), "pending"));
    }

    private void write(Consumer<AcmeMapper> work) {
        transaction(mapper -> {
            work.accept(mapper);
            return null;
        }, "Database update failed");
    }

    private <T> T read(Function<AcmeMapper, T> work) {
        try (SqlSession session = sessionFactory.openSession(true)) {
            return work.apply(session.getMapper(AcmeMapper.class));
        } catch (RuntimeException e) {
            throw new IllegalStateException("Database query failed", e);
        }
    }

    private <T> T transaction(Function<AcmeMapper, T> work, String errorMessage) {
        try (SqlSession session = sessionFactory.openSession(false)) {
            try {
                T result = work.apply(session.getMapper(AcmeMapper.class));
                session.commit();
                return result;
            } catch (RuntimeException e) {
                session.rollback();
                throw e;
            }
        } catch (RuntimeException e) {
            if (e instanceof AcmeException) {
                throw e;
            }
            throw new IllegalStateException(errorMessage, e);
        }
    }
}
