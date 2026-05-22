package com.elevenware.quickpki.acme;

import com.elevenware.quickpki.Csr;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Enforces that a finalize CSR only requests subjectAltName entries the order's
 * authorizations actually validated.
 * <p>
 * This is an ACME protocol obligation that belongs to the ACME server no matter
 * who signs the certificate: a remote certificate API issues whatever the CSR
 * asks for and knows nothing about ACME authorizations, so the check runs here
 * before either the local CA or the remote API sees the request.
 */
final class CsrValidation {

    private CsrValidation() {
    }

    /**
     * The parsed CSR plus the de-duplicated SAN entries it carries, ready to be
     * handed to a CA. {@code commonName} is just a stable label for the subject.
     */
    record ValidatedCsr(
            PKCS10CertificationRequest csr,
            List<String> dnsNames,
            List<String> ipNames,
            String commonName) {
    }

    static ValidatedCsr validate(byte[] csrDer, List<Identifier> validatedIdentifiers) {
        PKCS10CertificationRequest csr;
        try {
            csr = new PKCS10CertificationRequest(csrDer);
        } catch (Exception e) {
            throw new AcmeException(400, "badCSR", "Failed to parse PKCS#10 CSR: " + e.getMessage());
        }

        // Filter per-type: a validated "dns:example.com" identifier authorises a
        // dNSName SAN, not an iPAddress SAN of the same string. Carrying the tag
        // through avoids issuing a cert whose SAN type disagrees with what was
        // actually validated.
        Set<String> allowedDns = identifierValuesOfType(validatedIdentifiers, "dns");
        Set<String> allowedIp = identifierValuesOfType(validatedIdentifiers, "ip");

        List<String> csrDnsNames = Csr.dnsSubjectAlternativeNames(csr);
        List<String> csrIpNames = Csr.ipSubjectAlternativeNames(csr);

        if (!csrDnsNames.stream().allMatch(allowedDns::contains)
                || !csrIpNames.stream().allMatch(allowedIp::contains)) {
            throw new AcmeException(400, "badCSR",
                    "CSR contains subjectAltName entries that were not validated");
        }

        List<String> dnsNames = csrDnsNames.stream().distinct().toList();
        List<String> ipNames = csrIpNames.stream().distinct().toList();
        if (dnsNames.isEmpty() && ipNames.isEmpty()) {
            throw new AcmeException(400, "badCSR",
                    "CSR must contain at least one validated subjectAltName");
        }

        // CN is just a label - take the first SAN in CSR source order so it
        // stays stable across re-issuance.
        return new ValidatedCsr(csr, dnsNames, ipNames, Csr.subjectAlternativeNames(csr).get(0));
    }

    private static Set<String> identifierValuesOfType(List<Identifier> identifiers, String type) {
        return identifiers.stream()
                .filter(id -> type.equalsIgnoreCase(id.type()))
                .map(Identifier::value)
                .collect(Collectors.toCollection(HashSet::new));
    }
}
