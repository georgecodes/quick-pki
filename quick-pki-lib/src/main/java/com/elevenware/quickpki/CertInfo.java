package com.elevenware.quickpki;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.GeneralName;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public final class CertInfo {

    private final SubjectName subjectName;
    private final Instant validFrom;
    private final Instant validUntil;
    private final List<String> dnsNames;
    private final List<String> ipAddresses;
    private final List<String> uris;
    private final List<GeneralName> otherSubjectAlternativeNames;
    private final List<QcStatement> qcStatements;
    private final List<String> certificatePolicies;
    private final Set<KeyUsageBit> keyUsages;
    private final Set<ExtendedKeyUsageId> extendedKeyUsages;
    private final List<String> extendedKeyUsageOids;
    private final CertificateProfile profile;

    private CertInfo(Builder builder) {
        this.subjectName = builder.subjectName;
        this.validFrom = builder.validFrom;
        this.validUntil = builder.validUntil;
        this.dnsNames = List.copyOf(builder.dnsNames);
        this.ipAddresses = List.copyOf(builder.ipAddresses);
        this.uris = List.copyOf(builder.uris);
        this.otherSubjectAlternativeNames = List.copyOf(builder.otherSubjectAlternativeNames);
        this.qcStatements = List.copyOf(builder.qcStatements);
        this.certificatePolicies = List.copyOf(builder.certificatePolicies);
        this.extendedKeyUsageOids = List.copyOf(builder.extendedKeyUsageOids);
        // Never null: a CertInfo without an explicit profile behaves exactly
        // as QuickPki did before profiles existed.
        this.profile = builder.profile == null ? CertificateProfile.DEFAULT : builder.profile;
        // null vs non-null distinguishes 'use the algorithm-aware default'
        // from 'use exactly these'. Defensive copy; immutable view returned
        // from the getter.
        this.keyUsages = builder.keyUsages == null ? null
                : Collections.unmodifiableSet(EnumSet.copyOf(builder.keyUsages));
        this.extendedKeyUsages = builder.extendedKeyUsages == null ? null
                : Collections.unmodifiableSet(EnumSet.copyOf(builder.extendedKeyUsages));
        // Eager guard for the case where the caller set both fields. The
        // late case (one defaulted from IssuerInfo) is caught at issue time.
        if (this.validFrom != null && this.validUntil != null
                && this.validFrom.isAfter(this.validUntil)) {
            throw new IllegalArgumentException(
                    "validFrom (" + this.validFrom + ") must not be after validUntil ("
                            + this.validUntil + ")");
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns a {@link Builder} pre-populated with the subject DN and SAN
     * entries (dNSName / iPAddress) from {@code csr}. Validity and key/usage
     * fields are left at their defaults so the caller can layer their own
     * policy on top (eg. ACME validators that restrict SANs to validated
     * identifiers). This factory does not verify the CSR's signature;
     * {@link QuickPki#issueCertificate(PKCS10CertificationRequest, CertInfo)}
     * does that at issuance time.
     */
    public static Builder fromCsr(PKCS10CertificationRequest csr) {
        Objects.requireNonNull(csr, "csr must not be null");
        Builder builder = builder().subjectName(Csr.subjectName(csr));
        // Carry the dNSName / iPAddress tag through from the CSR rather than
        // re-detecting from the string - a CSR dNSName like "10.0.0.1"
        // (numeric labels are valid DNS) must stay a DNS SAN on the issued
        // cert.
        for (String name : Csr.dnsSubjectAlternativeNames(csr)) {
            builder.dnsName(name);
        }
        for (String ip : Csr.ipSubjectAlternativeNames(csr)) {
            builder.ipAddress(ip);
        }
        for (String uri : Csr.uriSubjectAlternativeNames(csr)) {
            builder.uri(uri);
        }
        for (GeneralName otherName : Csr.otherSubjectAlternativeNames(csr)) {
            builder.otherSubjectAlternativeName(otherName);
        }
        // QC statements live in the CSR's extensionRequest the same way SANs
        // do; carry them through so an EU qualified profile can be issued
        // from a CSR the subscriber built with EuQualified.qwac()/qseal().
        for (QcStatement statement : Csr.qcStatements(csr)) {
            builder.qcStatement(statement);
        }
        // certificatePolicies travels in the CSR's extensionRequest too;
        // carry the policy OIDs through so a Sesame OS_TRANSPORT / OS_SIGNING
        // profile can be issued straight from a CSR built with Sesame.os*().
        for (String policyOid : Csr.certificatePolicies(csr)) {
            builder.certificatePolicy(policyOid);
        }
        return builder;
    }

    public SubjectName getSubjectName() {
        return subjectName;
    }

    public Instant getValidFrom() {
        return validFrom;
    }

    public Instant getValidUntil() {
        return validUntil;
    }

    public List<String> getDnsNames() {
        return dnsNames;
    }

    public List<String> getIpAddresses() {
        return ipAddresses;
    }

    /**
     * URI subjectAltName entries (eg. {@code urn:odtf:finance:...}) to emit on
     * the issued certificate. Empty when the caller has set none.
     */
    public List<String> getUris() {
        return uris;
    }

    public List<GeneralName> getOtherSubjectAlternativeNames() {
        return otherSubjectAlternativeNames;
    }

    /**
     * Policy OIDs to emit in the leaf's {@code certificatePolicies} extension
     * (RFC 5280 §4.2.1.4). Empty list when the caller has set none; the
     * extension is omitted in that case.
     */
    public List<String> getCertificatePolicies() {
        return certificatePolicies;
    }

    /**
     * QCStatements to emit in the leaf's {@code qCStatements} extension. Empty
     * when the caller has set none; the extension is omitted in that case.
     */
    public List<QcStatement> getQcStatements() {
        return qcStatements;
    }

    // Null when the caller hasn't expressed a preference (QuickPki picks an
    // algorithm-aware default). Non-null when the caller specified an explicit
    // override via Builder.keyUsage(...).
    public Set<KeyUsageBit> getKeyUsages() {
        return keyUsages;
    }

    public Set<ExtendedKeyUsageId> getExtendedKeyUsages() {
        return extendedKeyUsages;
    }

    /**
     * Arbitrary ExtendedKeyUsage purpose OIDs to emit on the leaf in addition
     * to any {@link ExtendedKeyUsageId} values. Used by profiles that pin a
     * private OID (eg. Sesame OS_SIGNING). Empty when the caller has set none.
     * Like {@link #getExtendedKeyUsages()}, supplying any OID here counts as
     * an explicit override of the profile's default EKU set.
     */
    public List<String> getExtendedKeyUsageOids() {
        return extendedKeyUsageOids;
    }

    // The selected certificate profile; never null (defaults to
    // CertificateProfile.DEFAULT). The profile supplies KeyUsage /
    // ExtendedKeyUsage defaults that explicit Builder.keyUsage(...) /
    // Builder.extendedKeyUsage(...) calls still override.
    public CertificateProfile getProfile() {
        return profile;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CertInfo that)) return false;
        return Objects.equals(subjectName, that.subjectName)
                && Objects.equals(validFrom, that.validFrom)
                && Objects.equals(validUntil, that.validUntil)
                && Objects.equals(dnsNames, that.dnsNames)
                && Objects.equals(ipAddresses, that.ipAddresses)
                && Objects.equals(uris, that.uris)
                && Objects.equals(otherSubjectAlternativeNames, that.otherSubjectAlternativeNames)
                && Objects.equals(qcStatements, that.qcStatements)
                && Objects.equals(certificatePolicies, that.certificatePolicies)
                && Objects.equals(keyUsages, that.keyUsages)
                && Objects.equals(extendedKeyUsages, that.extendedKeyUsages)
                && Objects.equals(extendedKeyUsageOids, that.extendedKeyUsageOids)
                && profile == that.profile;
    }

    @Override
    public int hashCode() {
        return Objects.hash(subjectName, validFrom, validUntil, dnsNames,
                ipAddresses, uris, otherSubjectAlternativeNames, qcStatements,
                certificatePolicies, keyUsages, extendedKeyUsages,
                extendedKeyUsageOids, profile);
    }

    @Override
    public String toString() {
        return "CertInfo{"
                + "subjectName=" + subjectName
                + ", validFrom=" + validFrom
                + ", validUntil=" + validUntil
                + ", dnsNames=" + dnsNames
                + ", ipAddresses=" + ipAddresses
                + ", uris=" + uris
                + ", otherSubjectAlternativeNames=" + otherSubjectAlternativeNames
                + ", qcStatements=" + qcStatements
                + ", certificatePolicies=" + certificatePolicies
                + ", keyUsages=" + keyUsages
                + ", extendedKeyUsages=" + extendedKeyUsages
                + ", extendedKeyUsageOids=" + extendedKeyUsageOids
                + ", profile=" + profile
                + '}';
    }

    public static final class Builder {
        private SubjectName subjectName;
        private Instant validFrom;
        private Instant validUntil;
        private final List<String> dnsNames = new ArrayList<>();
        private final List<String> ipAddresses = new ArrayList<>();
        private final List<String> uris = new ArrayList<>();
        private final List<GeneralName> otherSubjectAlternativeNames = new ArrayList<>();
        private final List<QcStatement> qcStatements = new ArrayList<>();
        private final List<String> certificatePolicies = new ArrayList<>();
        private EnumSet<KeyUsageBit> keyUsages;
        private EnumSet<ExtendedKeyUsageId> extendedKeyUsages;
        private final List<String> extendedKeyUsageOids = new ArrayList<>();
        private CertificateProfile profile;

        private Builder() {
        }

        public Builder subjectName(SubjectName subjectName) {
            this.subjectName = subjectName;
            return this;
        }

        public Builder validFrom(Instant validFrom) {
            this.validFrom = validFrom;
            return this;
        }

        public Builder validUntil(Instant validUntil) {
            this.validUntil = validUntil;
            return this;
        }

        public Builder dnsName(String dnsName) {
            this.dnsNames.add(Objects.requireNonNull(dnsName, "dnsName must not be null"));
            return this;
        }

        public Builder ipAddress(String ipAddress) {
            this.ipAddresses.add(Objects.requireNonNull(ipAddress, "ipAddress must not be null"));
            return this;
        }

        /**
         * Adds a URI subjectAltName entry (RFC 5280 §4.2.1.6). Sesame
         * OS_TRANSPORT / OS_SIGNING certificates carry the participant and
         * software-statement URNs this way.
         */
        public Builder uri(String uri) {
            this.uris.add(Objects.requireNonNull(uri, "uri must not be null"));
            return this;
        }

        public Builder otherName(String oid, String printableString) {
            Objects.requireNonNull(oid, "oid must not be null");
            Objects.requireNonNull(printableString, "printableString must not be null");
            return otherSubjectAlternativeName(new GeneralName(GeneralName.otherName,
                    new DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
                            new ASN1ObjectIdentifier(oid),
                            new DERTaggedObject(true, 0, new DERPrintableString(printableString))
                    })));
        }

        public Builder otherSubjectAlternativeName(GeneralName name) {
            Objects.requireNonNull(name, "subjectAlternativeName must not be null");
            if (name.getTagNo() != GeneralName.otherName) {
                throw new IllegalArgumentException(
                        "subjectAlternativeName must be an otherName GeneralName");
            }
            this.otherSubjectAlternativeNames.add(name);
            return this;
        }

        /**
         * Adds a QCStatement (RFC 3739) to the leaf's {@code qCStatements}
         * extension. Multiple calls append in the order they were made.
         * {@link EuQualified} supplies factory methods for the standard ETSI
         * and PSD2 statements.
         */
        public Builder qcStatement(QcStatement statement) {
            this.qcStatements.add(Objects.requireNonNull(statement, "statement must not be null"));
            return this;
        }

        /**
         * Adds a policy OID to the leaf's {@code certificatePolicies}
         * extension (RFC 5280 §4.2.1.4). Multiple calls append.
         */
        public Builder certificatePolicy(String policyOid) {
            this.certificatePolicies.add(Objects.requireNonNull(policyOid,
                    "policyOid must not be null"));
            return this;
        }

        // Add a KeyUsage bit. Calling this any number of times overrides the
        // algorithm-aware default that QuickPki would otherwise pick. Unset
        // (no calls) means use the default. CA-only bits (keyCertSign,
        // cRLSign) are rejected here: CertInfo describes leaves, and the
        // resulting cert would have BasicConstraints(false) - which combined
        // with those bits is RFC 5280-invalid and rejected by PKIX
        // validators. Intermediates don't go through this path; they get
        // keyCertSign|cRLSign emitted directly by issueIntermediate.
        public Builder keyUsage(KeyUsageBit bit) {
            Objects.requireNonNull(bit, "keyUsage bit must not be null");
            if (bit == KeyUsageBit.KEY_CERT_SIGN || bit == KeyUsageBit.CRL_SIGN) {
                throw new IllegalArgumentException(
                        bit + " is a CA-only KeyUsage bit; it cannot appear on a leaf "
                                + "certificate. Use issueIntermediate(...) for CA certs.");
            }
            if (this.keyUsages == null) {
                this.keyUsages = EnumSet.noneOf(KeyUsageBit.class);
            }
            this.keyUsages.add(bit);
            return this;
        }

        // Add an ExtendedKeyUsage purpose. Same override semantics as
        // keyUsage(...) - default is serverAuth + clientAuth on leaves.
        public Builder extendedKeyUsage(ExtendedKeyUsageId id) {
            Objects.requireNonNull(id, "extendedKeyUsage id must not be null");
            if (this.extendedKeyUsages == null) {
                this.extendedKeyUsages = EnumSet.noneOf(ExtendedKeyUsageId.class);
            }
            this.extendedKeyUsages.add(id);
            return this;
        }

        /**
         * Adds an arbitrary ExtendedKeyUsage purpose OID to the leaf, used by
         * profiles that pin a private OID rather than one of the six standard
         * {@link ExtendedKeyUsageId} values (eg. Sesame OS_SIGNING's
         * ecosystem-specific signing EKU). Supplying any OID here counts as
         * an explicit override of the profile's default EKU set, just like
         * calling {@link #extendedKeyUsage(ExtendedKeyUsageId)}.
         */
        public Builder extendedKeyUsageOid(String oid) {
            this.extendedKeyUsageOids.add(Objects.requireNonNull(oid,
                    "extendedKeyUsage oid must not be null"));
            return this;
        }

        // Select a certificate profile (eg. CertificateProfile.BRCAC). The
        // profile supplies KeyUsage / ExtendedKeyUsage defaults for the leaf;
        // explicit keyUsage(...) / extendedKeyUsage(...) calls on this builder
        // still take precedence. Unset means CertificateProfile.DEFAULT.
        public Builder profile(CertificateProfile profile) {
            this.profile = Objects.requireNonNull(profile, "profile must not be null");
            return this;
        }

        public CertInfo build() {
            return new CertInfo(this);
        }
    }
}
