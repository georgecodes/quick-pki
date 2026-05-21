package com.elevenware.quickpki;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.net.InetAddress;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Helpers for {@link PKCS10CertificationRequest} (CSR) introspection.
 * <p>
 * Used by {@link QuickPki#issueCertificate(PKCS10CertificationRequest)} and
 * {@link CertInfo#fromCsr(PKCS10CertificationRequest)}, and exposed for callers
 * that need to apply their own policy on top of CSR contents (eg. ACME servers
 * filtering SANs against validated identifiers).
 */
public final class Csr {

    private Csr() {}

    /**
     * Verifies the CSR's self-signature using the public key embedded in it.
     * Throws if the signature is invalid or cannot be verified - never silently
     * accepts an unverifiable CSR.
     *
     * @throws QuickPkiException if the signature is invalid or verification fails
     */
    public static void verifySignature(PKCS10CertificationRequest csr) {
        Objects.requireNonNull(csr, "csr must not be null");
        Provider provider = ensureBouncyCastleProvider();
        try {
            boolean valid = csr.isSignatureValid(new JcaContentVerifierProviderBuilder()
                    .setProvider(provider)
                    .build(csr.getSubjectPublicKeyInfo()));
            if (!valid) {
                throw new QuickPkiException("CSR signature is invalid");
            }
        } catch (QuickPkiException e) {
            throw e;
        } catch (Exception e) {
            throw new QuickPkiException("Failed to verify CSR signature", e);
        }
    }

    /**
     * Extracts the subscriber's public key from the CSR.
     */
    public static PublicKey publicKey(PKCS10CertificationRequest csr) {
        Objects.requireNonNull(csr, "csr must not be null");
        try {
            return new JcaPKCS10CertificationRequest(csr)
                    .setProvider(ensureBouncyCastleProvider())
                    .getPublicKey();
        } catch (Exception e) {
            throw new QuickPkiException("Failed to extract public key from CSR", e);
        }
    }

    /**
     * Converts the CSR's subject DN into a {@link SubjectName}. RDNs the
     * SubjectName builder doesn't model are silently dropped.
     */
    public static SubjectName subjectName(PKCS10CertificationRequest csr) {
        Objects.requireNonNull(csr, "csr must not be null");
        X500Name subject = csr.getSubject();
        SubjectName.Builder builder = SubjectName.builder();
        applyRdn(subject, BCStyle.CN, builder::commonName);
        applyRdn(subject, BCStyle.C, builder::country);
        applyRdn(subject, BCStyle.O, builder::organization);
        applyRdn(subject, BCStyle.OU, builder::organizationUnit);
        applyRdn(subject, BCStyle.DN_QUALIFIER, builder::dnQualifier);
        applyRdn(subject, BCStyle.L, builder::locality);
        applyRdn(subject, BCStyle.ST, builder::stateOrProvince);
        return builder.build();
    }

    /**
     * Returns the dNSName and iPAddress entries from the CSR's requested
     * subjectAltName extension. Mixed types in source order; empty list if the
     * CSR omitted the extension or it contained only other GeneralName types.
     */
    public static List<String> subjectAlternativeNames(PKCS10CertificationRequest csr) {
        Objects.requireNonNull(csr, "csr must not be null");
        Extensions extensions = csr.getRequestedExtensions();
        if (extensions == null) {
            return List.of();
        }
        GeneralNames generalNames = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
        if (generalNames == null) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (GeneralName name : generalNames.getNames()) {
            if (name.getTagNo() == GeneralName.dNSName) {
                result.add(name.getName().toString());
            } else if (name.getTagNo() == GeneralName.iPAddress) {
                result.add(decodeIpAddress(name));
            }
        }
        return List.copyOf(result);
    }

    /**
     * Best-effort classification of a SAN string as an IP literal (v4 or v6)
     * rather than a DNS name. Matches what the SAN extension would emit for
     * the value.
     */
    public static boolean isIpAddress(String value) {
        Objects.requireNonNull(value, "value must not be null");
        try {
            InetAddress.getByName(value);
        } catch (Exception e) {
            return false;
        }
        // getByName resolves DNS too; restrict to literal forms (digits/dots
        // for v4, colon-bearing for v6) so we don't classify "example.com" as
        // an IP just because it resolves.
        return value.indexOf(':') >= 0
                || value.chars().allMatch(c -> Character.isDigit(c) || c == '.');
    }

    private static String decodeIpAddress(GeneralName name) {
        try {
            byte[] octets = ASN1OctetString.getInstance(name.getName()).getOctets();
            return InetAddress.getByAddress(octets).getHostAddress();
        } catch (Exception e) {
            throw new QuickPkiException("CSR contains an invalid IP subjectAltName", e);
        }
    }

    private static void applyRdn(X500Name name, org.bouncycastle.asn1.ASN1ObjectIdentifier oid,
                                 java.util.function.Consumer<String> setter) {
        RDN[] rdns = name.getRDNs(oid);
        if (rdns == null || rdns.length == 0) {
            return;
        }
        setter.accept(IETFUtils.valueToString(rdns[0].getFirst().getValue()));
    }

    private static Provider ensureBouncyCastleProvider() {
        Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (provider == null) {
            provider = new BouncyCastleProvider();
            Security.addProvider(provider);
        }
        return provider;
    }
}
