package com.elevenware.quickpki.acme;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

interface AcmeMapper {

    @Select("""
            select issuer_info_json,
                   certificate_pem,
                   private_key_ciphertext,
                   private_key_salt,
                   private_key_iv
            from ca_material
            where id = #{id}
            """)
    CaMaterial selectCaMaterial(String id);

    @Update("""
            update ca_material
            set issuer_info_json = #{issuerInfoJson},
                certificate_pem = #{certificatePem},
                private_key_ciphertext = #{privateKeyCiphertext},
                private_key_salt = #{privateKeySalt},
                private_key_iv = #{privateKeyIv},
                created_at = now()
            where id = #{id}
            """)
    int updateCaMaterial(CaMaterialWrite material);

    @Insert("""
            insert into ca_material (
                id,
                issuer_info_json,
                certificate_pem,
                private_key_ciphertext,
                private_key_salt,
                private_key_iv
            ) values (
                #{id},
                #{issuerInfoJson},
                #{certificatePem},
                #{privateKeyCiphertext},
                #{privateKeySalt},
                #{privateKeyIv}
            )
            """)
    int insertCaMaterial(CaMaterialWrite material);

    @Select("""
            select id,
                   key_thumbprint,
                   jwk_json,
                   contact_json,
                   status,
                   terms_agreed
            from acme_accounts
            where key_thumbprint = #{thumbprint}
            """)
    Account selectAccountByThumbprint(String thumbprint);

    @Select("""
            select id,
                   key_thumbprint,
                   jwk_json,
                   contact_json,
                   status,
                   terms_agreed
            from acme_accounts
            where id = #{id}
            """)
    Account selectAccount(UUID id);

    @Insert("""
            insert into acme_accounts (
                id,
                key_thumbprint,
                jwk_json,
                contact_json,
                status,
                terms_agreed
            ) values (
                #{id},
                #{keyThumbprint},
                #{jwkJson},
                #{contactJson},
                #{status},
                #{termsAgreed}
            )
            """)
    int insertAccount(Account account);

    @Insert("""
            insert into acme_orders (
                id,
                account_id,
                status,
                expires_at,
                identifiers_json
            ) values (
                #{id},
                #{accountId},
                #{status},
                #{expiresAt},
                #{identifiersJson}
            )
            """)
    int insertOrder(OrderWrite order);

    @Select("""
            select id,
                   account_id,
                   status,
                   expires_at,
                   identifiers_json,
                   csr_der,
                   certificate_pem,
                   chain_pem
            from acme_orders
            where id = #{id}
            """)
    OrderRow selectOrder(UUID id);

    @Select("""
            select id,
                   account_id,
                   status,
                   expires_at,
                   identifiers_json,
                   csr_der,
                   certificate_pem,
                   chain_pem
            from acme_orders
            where account_id = #{accountId}
            order by created_at desc
            """)
    List<OrderRow> selectOrdersForAccount(UUID accountId);

    @Update("""
            update acme_orders
            set status = #{status},
                csr_der = #{csrDer},
                certificate_pem = #{certificatePem},
                chain_pem = #{chainPem}
            where id = #{id}
            """)
    int completeOrder(OrderCompletion completion);

    @Update("""
            update acme_orders
            set status = 'ready'
            where id = #{orderId}
              and status = 'pending'
            """)
    int markOrderReadyIfPending(UUID orderId);

    @Update("""
            update acme_orders
            set status = 'invalid'
            where id = #{orderId}
              and status in ('pending', 'ready', 'processing')
            """)
    int markOrderInvalidIfActive(UUID orderId);

    @Insert("""
            insert into acme_authorizations (
                id,
                order_id,
                identifier_type,
                identifier_value,
                wildcard,
                status,
                expires_at
            ) values (
                #{id},
                #{orderId},
                #{identifierType},
                #{identifierValue},
                #{wildcard},
                #{status},
                #{expiresAt}
            )
            """)
    int insertAuthorization(AuthorizationWrite authorization);

    @Select("""
            select id,
                   order_id,
                   identifier_type,
                   identifier_value,
                   wildcard,
                   status,
                   expires_at
            from acme_authorizations
            where id = #{id}
            """)
    AuthorizationRow selectAuthorization(UUID id);

    @Select("""
            select a.id,
                   a.order_id,
                   a.identifier_type,
                   a.identifier_value,
                   a.wildcard,
                   a.status,
                   a.expires_at
            from acme_authorizations a
            join acme_challenges c on c.authorization_id = a.id
            where c.id = #{challengeId}
            """)
    AuthorizationRow selectAuthorizationForChallenge(UUID challengeId);

    @Select("""
            select id,
                   order_id,
                   identifier_type,
                   identifier_value,
                   wildcard,
                   status,
                   expires_at
            from acme_authorizations
            where order_id = #{orderId}
            order by id
            """)
    List<AuthorizationRow> selectAuthorizationsForOrder(UUID orderId);

    @Select("""
            select authorization_id
            from acme_challenges
            where id = #{challengeId}
            """)
    UUID selectAuthorizationIdForChallenge(UUID challengeId);

    @Select("""
            select order_id
            from acme_authorizations
            where id = #{authorizationId}
            """)
    UUID selectOrderIdForAuthorization(UUID authorizationId);

    @Update("""
            update acme_authorizations
            set status = #{status}
            where id = #{authorizationId}
            """)
    int updateAuthorizationStatus(@Param("authorizationId") UUID authorizationId, @Param("status") String status);

    @Select("""
            select count(*)
            from acme_authorizations
            where order_id = #{orderId}
              and status <> 'valid'
            """)
    int countNonValidAuthorizations(UUID orderId);

    @Insert("""
            insert into acme_challenges (
                id,
                authorization_id,
                type,
                token,
                status
            ) values (
                #{id},
                #{authorizationId},
                #{type},
                #{token},
                #{status}
            )
            """)
    int insertChallenge(ChallengeWrite challenge);

    @Select("""
            select id,
                   authorization_id,
                   type,
                   token,
                   status,
                   validated_at,
                   error_json
            from acme_challenges
            where id = #{id}
            """)
    Challenge selectChallenge(UUID id);

    @Select("""
            select id,
                   authorization_id,
                   type,
                   token,
                   status,
                   validated_at,
                   error_json
            from acme_challenges
            where authorization_id = #{authorizationId}
            order by type
            """)
    List<Challenge> selectChallengesForAuthorization(UUID authorizationId);

    @Update("""
            update acme_challenges
            set status = 'valid',
                validated_at = #{validatedAt}
            where id = #{challengeId}
            """)
    int markChallengeValid(@Param("challengeId") UUID challengeId, @Param("validatedAt") Instant validatedAt);

    @Update("""
            update acme_challenges
            set status = 'invalid',
                error_json = #{errorJson}
            where id = #{challengeId}
            """)
    int markChallengeInvalid(@Param("challengeId") UUID challengeId, @Param("errorJson") String errorJson);
}

record CaMaterialWrite(
        String id,
        String issuerInfoJson,
        String certificatePem,
        byte[] privateKeyCiphertext,
        byte[] privateKeySalt,
        byte[] privateKeyIv
) {
}

record OrderWrite(UUID id, UUID accountId, String status, Instant expiresAt, String identifiersJson) {
}

record OrderRow(
        UUID id,
        UUID accountId,
        String status,
        Instant expiresAt,
        String identifiersJson,
        byte[] csrDer,
        String certificatePem,
        String chainPem
) {

    Order toOrder(List<Authorization> authorizations) {
        return new Order(id, accountId, status, expiresAt, identifiersJson, csrDer, certificatePem, chainPem,
                authorizations);
    }
}

record OrderCompletion(UUID id, String status, byte[] csrDer, String certificatePem, String chainPem) {
}

record AuthorizationWrite(
        UUID id,
        UUID orderId,
        String identifierType,
        String identifierValue,
        boolean wildcard,
        String status,
        Instant expiresAt
) {
}

record AuthorizationRow(
        UUID id,
        UUID orderId,
        String identifierType,
        String identifierValue,
        boolean wildcard,
        String status,
        Instant expiresAt
) {

    Authorization toAuthorization(List<Challenge> challenges) {
        return new Authorization(id, orderId, identifierType, identifierValue, wildcard, status, expiresAt, challenges);
    }
}

record ChallengeWrite(UUID id, UUID authorizationId, String type, String token, String status) {
}
