package com.elevenware.quickpki.acme;

import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AcmeRepositoryTest {

    @Test
    void createsAccountsOrdersAuthorizationsAndChallenges() throws Exception {
        AcmeRepository repository = new AcmeRepository(AcmeTestSupport.dataSource());
        Account account = repository.createAccount("thumbprint", "{\"kty\":\"RSA\"}", "[\"mailto:admin@example.test\"]", true);

        Order order = repository.createOrder(account, List.of(new Identifier("dns", "example.test")), AcmeTestSupport.config());

        assertEquals("pending", order.status());
        assertEquals(account.id(), order.accountId());
        assertEquals(List.of(new Identifier("dns", "example.test")), repository.identifiers(order));
        assertEquals(1, order.authorizations().size());
        assertEquals("pending", order.authorizations().get(0).status());
        assertEquals(2, order.authorizations().get(0).challenges().size());
    }

    @Test
    void saveCaMaterialUpsertsDefaultRow() throws Exception {
        DataSource dataSource = AcmeTestSupport.dataSource();
        AcmeRepository repository = new AcmeRepository(dataSource);

        repository.saveCaMaterial(new CaMaterial("{}", "first", new byte[]{1}, new byte[]{2}, new byte[]{3}));
        repository.saveCaMaterial(new CaMaterial("{}", "second", new byte[]{4}, new byte[]{5}, new byte[]{6}));

        CaMaterial loaded = repository.loadCaMaterial().orElseThrow();
        assertEquals("second", loaded.certificatePem());
        assertTrue(java.util.Arrays.equals(new byte[]{4}, loaded.privateKeyCiphertext()));
        assertFalse(java.util.Arrays.equals(new byte[]{1}, loaded.privateKeyCiphertext()));
    }
}
