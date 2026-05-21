package com.elevenware.quickpki;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

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
    private final Set<KeyUsageBit> keyUsages;
    private final Set<ExtendedKeyUsageId> extendedKeyUsages;

    private CertInfo(Builder builder) {
        this.subjectName = builder.subjectName;
        this.validFrom = builder.validFrom;
        this.validUntil = builder.validUntil;
        this.dnsNames = List.copyOf(builder.dnsNames);
        this.ipAddresses = List.copyOf(builder.ipAddresses);
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
        for (String name : Csr.subjectAlternativeNames(csr)) {
            if (Csr.isIpAddress(name)) {
                builder.ipAddress(name);
            } else {
                builder.dnsName(name);
            }
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

    // Null when the caller hasn't expressed a preference (QuickPki picks an
    // algorithm-aware default). Non-null when the caller specified an explicit
    // override via Builder.keyUsage(...).
    public Set<KeyUsageBit> getKeyUsages() {
        return keyUsages;
    }

    public Set<ExtendedKeyUsageId> getExtendedKeyUsages() {
        return extendedKeyUsages;
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
                && Objects.equals(keyUsages, that.keyUsages)
                && Objects.equals(extendedKeyUsages, that.extendedKeyUsages);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subjectName, validFrom, validUntil, dnsNames,
                ipAddresses, keyUsages, extendedKeyUsages);
    }

    @Override
    public String toString() {
        return "CertInfo{"
                + "subjectName=" + subjectName
                + ", validFrom=" + validFrom
                + ", validUntil=" + validUntil
                + ", dnsNames=" + dnsNames
                + ", ipAddresses=" + ipAddresses
                + ", keyUsages=" + keyUsages
                + ", extendedKeyUsages=" + extendedKeyUsages
                + '}';
    }

    public static final class Builder {
        private SubjectName subjectName;
        private Instant validFrom;
        private Instant validUntil;
        private final List<String> dnsNames = new ArrayList<>();
        private final List<String> ipAddresses = new ArrayList<>();
        private EnumSet<KeyUsageBit> keyUsages;
        private EnumSet<ExtendedKeyUsageId> extendedKeyUsages;

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

        public CertInfo build() {
            return new CertInfo(this);
        }
    }
}
