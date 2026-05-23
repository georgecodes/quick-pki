package com.elevenware.quickpki;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.PrivateKey;
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
    static final ASN1ObjectIdentifier JURISDICTION_COUNTRY_NAME =
            new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.3");

    private Csr() {}

    /**
     * Builds a signed PKCS#10 certificate signing request from a
     * {@link CertInfo} and the subscriber's key pair. The CSR carries the
     * subject DN derived from the CertInfo's {@link SubjectName} (RDN ordering
     * follows the CertInfo's {@link CertificateProfile}) and a requested
     * subjectAltName extension built from the CertInfo's DNS / IP / otherName
     * entries. The signature is produced with an algorithm matched to the
     * private key (SHA256withRSA for RSA, SHA256withECDSA for EC, Ed25519 /
     * Ed448 for the EdDSA families).
     *
     * <p>This helper performs no profile-compliance validation; that runs at
     * issuance time inside {@link QuickPki#issueCertificate(PKCS10CertificationRequest)}.
     *
     * @throws QuickPkiException if signing fails
     * @throws IllegalArgumentException if the CertInfo carries no SubjectName
     *         or the key algorithm has no defined default signature algorithm
     */
    public static PKCS10CertificationRequest create(CertInfo info, KeyPair keyPair) {
        Objects.requireNonNull(info, "info must not be null");
        Objects.requireNonNull(keyPair, "keyPair must not be null");
        Objects.requireNonNull(keyPair.getPublic(), "keyPair public key must not be null");
        Objects.requireNonNull(keyPair.getPrivate(), "keyPair private key must not be null");
        SubjectName subjectName = info.getSubjectName();
        if (subjectName == null) {
            throw new IllegalArgumentException("CertInfo must carry a SubjectName to build a CSR");
        }
        Provider provider = ensureBouncyCastleProvider();
        X500Name subject = x500Name(subjectName, info.getProfile());
        PKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

        List<GeneralName> sans = new ArrayList<>();
        for (String dnsName : info.getDnsNames()) {
            sans.add(new GeneralName(GeneralName.dNSName, dnsName));
        }
        for (String ipAddress : info.getIpAddresses()) {
            sans.add(new GeneralName(GeneralName.iPAddress, ipAddress));
        }
        sans.addAll(info.getOtherSubjectAlternativeNames());
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        try {
            if (!sans.isEmpty()) {
                extGen.addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(sans.toArray(new GeneralName[0])));
            }
            if (!info.getQcStatements().isEmpty()) {
                extGen.addExtension(Extension.qCStatements, false,
                        encodeQcStatements(info.getQcStatements()));
            }
        } catch (IOException e) {
            throw new QuickPkiException("Failed to build CSR extensionRequest", e);
        }
        if (!extGen.isEmpty()) {
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        }

        try {
            ContentSigner signer = new JcaContentSignerBuilder(
                    signatureAlgorithmFor(keyPair.getPrivate()))
                    .setProvider(provider)
                    .build(keyPair.getPrivate());
            return builder.build(signer);
        } catch (Exception e) {
            throw new QuickPkiException("Failed to build CSR", e);
        }
    }

    /**
     * Encodes a CSR as a PEM string with a {@code CERTIFICATE REQUEST} label.
     */
    public static String toPem(PKCS10CertificationRequest csr) {
        Objects.requireNonNull(csr, "csr must not be null");
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(csr);
        } catch (IOException e) {
            throw new QuickPkiException("Failed to PEM-encode CSR", e);
        }
        return sw.toString();
    }

    /**
     * Parses a PEM-encoded CSR back into a {@link PKCS10CertificationRequest}.
     *
     * @throws QuickPkiException if the input is not a PEM CSR or cannot be parsed
     */
    public static PKCS10CertificationRequest fromPem(String pem) {
        Objects.requireNonNull(pem, "pem must not be null");
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            if (obj instanceof PKCS10CertificationRequest csr) {
                return csr;
            }
            String found = obj == null ? "nothing" : obj.getClass().getSimpleName();
            throw new QuickPkiException("PEM does not contain a CSR (found " + found + ")");
        } catch (IOException e) {
            throw new QuickPkiException("Failed to parse CSR from PEM", e);
        }
    }

    /**
     * Builds a subject X.500 name from a {@link SubjectName}, honouring the
     * RDN order required by the supplied {@link CertificateProfile}. Open
     * Finance Brasil profiles emit RDNs in the spec-mandated order; the
     * default branch emits whichever RDNs are present in source order. Null
     * or blank fields are skipped, so a partially-populated SubjectName
     * produces a partial DN rather than throwing.
     *
     * <p>Exposed so services that build their own PKCS#10 CSRs (eg. the
     * cert-api server-side BRCAC/BRSEAL convenience endpoints) can reuse the
     * profile-aware RDN ordering without re-implementing it.
     */
    public static X500Name x500Name(SubjectName info, CertificateProfile profile) {
        Objects.requireNonNull(info, "info must not be null");
        // commonName is the single RDN every leaf subject must carry. The
        // OF profile validators also check it, but enforcing here means
        // Csr.create gets the same fail-fast guarantee regardless of profile.
        Objects.requireNonNull(info.getCommonName(), "commonName must not be null");
        CertificateProfile effective = profile == null ? CertificateProfile.DEFAULT : profile;
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        if (effective == CertificateProfile.BRCAC) {
            addRdnIfPresent(builder, BCStyle.BUSINESS_CATEGORY, info.getBusinessCategory());
            addRdnIfPresent(builder, JURISDICTION_COUNTRY_NAME, info.getJurisdictionCountry());
            addRdnIfPresent(builder, BCStyle.SERIALNUMBER, info.getSerialNumber());
            addRdnIfPresent(builder, BCStyle.C, info.getCountry());
            addRdnIfPresent(builder, BCStyle.O, info.getOrganization());
            addRdnIfPresent(builder, BCStyle.ST, info.getStateOrProvince());
            addRdnIfPresent(builder, BCStyle.L, info.getLocality());
            addRdnIfPresent(builder, BCStyle.ORGANIZATION_IDENTIFIER, info.getOrganizationIdentifier());
            addRdnIfPresent(builder, BCStyle.UID, info.getUserId());
            addRdnIfPresent(builder, BCStyle.CN, info.getCommonName());
            return builder.build();
        }
        if (effective == CertificateProfile.BRSEAL) {
            addRdnIfPresent(builder, BCStyle.UID, info.getUserId());
            addRdnIfPresent(builder, BCStyle.C, info.getCountry());
            addRdnIfPresent(builder, BCStyle.O, info.getOrganization());
            for (String organizationUnit : info.getOrganizationUnits()) {
                addRdnIfPresent(builder, BCStyle.OU, organizationUnit);
            }
            addRdnIfPresent(builder, BCStyle.CN, info.getCommonName());
            return builder.build();
        }
        if (effective == CertificateProfile.QWAC || effective == CertificateProfile.QSEAL) {
            // ETSI EN 319 412-1 §5.1.2 / -3 §4.2 subject DN order for
            // legal-person qualified certs. countryName first, then the EV
            // attributes, then the organizationIdentifier required by
            // ETSI EN 319 412-1 §5.1.4 (PSDxx-NCA-PSP for PSD2 contexts),
            // commonName last.
            addRdnIfPresent(builder, BCStyle.C, info.getCountry());
            addRdnIfPresent(builder, BCStyle.ST, info.getStateOrProvince());
            addRdnIfPresent(builder, BCStyle.L, info.getLocality());
            addRdnIfPresent(builder, BCStyle.O, info.getOrganization());
            for (String organizationUnit : info.getOrganizationUnits()) {
                addRdnIfPresent(builder, BCStyle.OU, organizationUnit);
            }
            addRdnIfPresent(builder, BCStyle.SERIALNUMBER, info.getSerialNumber());
            addRdnIfPresent(builder, BCStyle.ORGANIZATION_IDENTIFIER, info.getOrganizationIdentifier());
            addRdnIfPresent(builder, BCStyle.CN, info.getCommonName());
            return builder.build();
        }
        addRdnIfPresent(builder, BCStyle.CN, info.getCommonName());
        addRdnIfPresent(builder, BCStyle.C, info.getCountry());
        addRdnIfPresent(builder, BCStyle.O, info.getOrganization());
        for (String organizationUnit : info.getOrganizationUnits()) {
            addRdnIfPresent(builder, BCStyle.OU, organizationUnit);
        }
        addRdnIfPresent(builder, BCStyle.DN_QUALIFIER, info.getDnQualifier());
        addRdnIfPresent(builder, BCStyle.L, info.getLocality());
        addRdnIfPresent(builder, BCStyle.ST, info.getStateOrProvince());
        addRdnIfPresent(builder, BCStyle.ORGANIZATION_IDENTIFIER, info.getOrganizationIdentifier());
        addRdnIfPresent(builder, BCStyle.BUSINESS_CATEGORY, info.getBusinessCategory());
        addRdnIfPresent(builder, JURISDICTION_COUNTRY_NAME, info.getJurisdictionCountry());
        addRdnIfPresent(builder, BCStyle.SERIALNUMBER, info.getSerialNumber());
        addRdnIfPresent(builder, BCStyle.UID, info.getUserId());
        return builder.build();
    }

    private static void addRdnIfPresent(X500NameBuilder builder, ASN1ObjectIdentifier oid, String value) {
        if (value != null && !value.isBlank()) {
            builder.addRDN(oid, value);
        }
    }

    private static String signatureAlgorithmFor(PrivateKey key) {
        String alg = key.getAlgorithm();
        if (alg == null) {
            throw new IllegalArgumentException("private key has no algorithm");
        }
        return switch (alg) {
            case "RSA" -> "SHA256withRSA";
            case "EC", "ECDSA" -> "SHA256withECDSA";
            case "Ed25519" -> "Ed25519";
            case "Ed448" -> "Ed448";
            default -> throw new IllegalArgumentException(
                    "no default CSR signature algorithm for key type " + alg);
        };
    }

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
     * Returns the QCStatements (RFC 3739) requested in the CSR's
     * extensionRequest, preserving each statement's ASN.1 payload. Empty list
     * when the CSR omitted the extension. Used by
     * {@link CertInfo#fromCsr(PKCS10CertificationRequest)} to carry the EU
     * qualified statements (QcCompliance, QcType, QcPDS, PSD2 qcStatement)
     * through to the issued certificate.
     */
    public static List<QcStatement> qcStatements(PKCS10CertificationRequest csr) {
        Objects.requireNonNull(csr, "csr must not be null");
        Extensions extensions = csr.getRequestedExtensions();
        if (extensions == null) {
            return List.of();
        }
        Extension qcExt = extensions.getExtension(Extension.qCStatements);
        if (qcExt == null) {
            return List.of();
        }
        ASN1Sequence sequence;
        try {
            sequence = ASN1Sequence.getInstance(qcExt.getParsedValue());
        } catch (Exception e) {
            throw new QuickPkiException("CSR carries a malformed qCStatements extension", e);
        }
        List<QcStatement> result = new ArrayList<>(sequence.size());
        for (int i = 0; i < sequence.size(); i++) {
            ASN1Sequence stmt = ASN1Sequence.getInstance(sequence.getObjectAt(i));
            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(stmt.getObjectAt(0));
            ASN1Encodable info = stmt.size() > 1 ? stmt.getObjectAt(1) : null;
            result.add(new QcStatement(oid, info));
        }
        return List.copyOf(result);
    }

    /**
     * Encodes a list of {@link QcStatement}s as the {@code SEQUENCE OF
     * QCStatement} structure mandated by RFC 3739 §3.2.6, ready to wrap in an
     * X.509 Extension value or hand to openssl as a {@code DER:} blob.
     */
    public static DERSequence encodeQcStatements(List<QcStatement> statements) {
        ASN1Encodable[] entries = new ASN1Encodable[statements.size()];
        for (int i = 0; i < statements.size(); i++) {
            QcStatement s = statements.get(i);
            if (s.statementInfo() == null) {
                entries[i] = new DERSequence(s.statementId());
            } else {
                entries[i] = new DERSequence(new ASN1Encodable[] {
                        s.statementId(), s.statementInfo()
                });
            }
        }
        return new DERSequence(entries);
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
