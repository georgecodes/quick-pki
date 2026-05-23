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

    // jurisdictionCountryName; BCStyle has no constant for this OID.
    private static final org.bouncycastle.asn1.ASN1ObjectIdentifier JURISDICTION_COUNTRY_NAME =
            new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.3");

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
        applyRdns(subject, BCStyle.OU, builder::addOrganizationUnit);
        applyRdn(subject, BCStyle.DN_QUALIFIER, builder::dnQualifier);
        applyRdn(subject, BCStyle.L, builder::locality);
        applyRdn(subject, BCStyle.ST, builder::stateOrProvince);
        applyRdn(subject, BCStyle.ORGANIZATION_IDENTIFIER, builder::organizationIdentifier);
        applyRdn(subject, BCStyle.BUSINESS_CATEGORY, builder::businessCategory);
        applyRdn(subject, JURISDICTION_COUNTRY_NAME, builder::jurisdictionCountry);
        applyRdn(subject, BCStyle.SERIALNUMBER, builder::serialNumber);
        applyRdn(subject, BCStyle.UID, builder::userId);
        return builder.build();
    }

    /**
     * Returns the dNSName entries from the CSR's requested subjectAltName
     * extension, in source order. Empty list if the CSR omitted the extension
     * or contained no dNSName entries.
     */
    public static List<String> dnsSubjectAlternativeNames(PKCS10CertificationRequest csr) {
        return sansOfTag(csr, GeneralName.dNSName);
    }

    /**
     * Returns the iPAddress entries from the CSR's requested subjectAltName
     * extension, in source order. Each entry is the textual form (dotted-quad
     * for v4, colon-hex for v6). Empty list if the CSR omitted the extension
     * or contained no iPAddress entries.
     */
    public static List<String> ipSubjectAlternativeNames(PKCS10CertificationRequest csr) {
        return sansOfTag(csr, GeneralName.iPAddress);
    }

    /**
     * Returns otherName SAN entries from the CSR's requested subjectAltName
     * extension, preserving the original ASN.1 value. Open Finance Brasil
     * BRSEAL certificates use ICP-Brasil otherName entries that callers need
     * to carry through unchanged from a CSR into the issued certificate.
     */
    public static List<GeneralName> otherSubjectAlternativeNames(PKCS10CertificationRequest csr) {
        Objects.requireNonNull(csr, "csr must not be null");
        Extensions extensions = csr.getRequestedExtensions();
        if (extensions == null) {
            return List.of();
        }
        GeneralNames generalNames = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
        if (generalNames == null) {
            return List.of();
        }
        List<GeneralName> result = new ArrayList<>();
        for (GeneralName name : generalNames.getNames()) {
            if (name.getTagNo() == GeneralName.otherName) {
                result.add(name);
            }
        }
        return List.copyOf(result);
    }

    /**
     * Returns dNSName and iPAddress entries from the CSR's requested
     * subjectAltName extension mixed together as strings, in source order.
     * The tag is lost - callers that need to round-trip the type (eg. when
     * building a new SAN extension on the issued cert) must use
     * {@link #dnsSubjectAlternativeNames(PKCS10CertificationRequest)} and
     * {@link #ipSubjectAlternativeNames(PKCS10CertificationRequest)}
     * instead, otherwise a dNSName that happens to look like an IP literal
     * (numeric labels are valid DNS syntax) will be silently re-typed.
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
     * Returns true if {@code value} is an IP literal (dotted-quad IPv4 or
     * colon-bearing IPv6). Shape-checks the string before any parser call so a
     * DNS name never triggers a name-service lookup.
     * <p>
     * This is a heuristic on bare strings; callers that already have a CSR in
     * hand should use {@link #dnsSubjectAlternativeNames} /
     * {@link #ipSubjectAlternativeNames} to preserve the actual SAN tag
     * rather than re-classify by shape.
     */
    public static boolean isIpAddress(String value) {
        Objects.requireNonNull(value, "value must not be null");
        boolean looksLikeV6 = value.indexOf(':') >= 0;
        boolean looksLikeV4 = !value.isEmpty()
                && value.chars().allMatch(c -> Character.isDigit(c) || c == '.');
        if (!looksLikeV4 && !looksLikeV6) {
            return false;
        }
        try {
            InetAddress.getByName(value);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static List<String> sansOfTag(PKCS10CertificationRequest csr, int tagNo) {
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
            if (name.getTagNo() != tagNo) {
                continue;
            }
            if (tagNo == GeneralName.iPAddress) {
                result.add(decodeIpAddress(name));
            } else {
                result.add(name.getName().toString());
            }
        }
        return List.copyOf(result);
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

    private static void applyRdns(X500Name name, org.bouncycastle.asn1.ASN1ObjectIdentifier oid,
                                  java.util.function.Consumer<String> setter) {
        RDN[] rdns = name.getRDNs(oid);
        if (rdns == null) {
            return;
        }
        for (RDN rdn : rdns) {
            setter.accept(IETFUtils.valueToString(rdn.getFirst().getValue()));
        }
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
