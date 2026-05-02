package com.elevenware.quickpki;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class CertInfo {

    private final SubjectName subjectName;
    private final Instant validFrom;
    private final Instant validUntil;
    private final List<String> dnsNames;
    private final List<String> ipAddresses;

    private CertInfo(Builder builder) {
        this.subjectName = builder.subjectName;
        this.validFrom = builder.validFrom;
        this.validUntil = builder.validUntil;
        this.dnsNames = List.copyOf(builder.dnsNames);
        this.ipAddresses = List.copyOf(builder.ipAddresses);
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CertInfo that)) return false;
        return Objects.equals(subjectName, that.subjectName)
                && Objects.equals(validFrom, that.validFrom)
                && Objects.equals(validUntil, that.validUntil)
                && Objects.equals(dnsNames, that.dnsNames)
                && Objects.equals(ipAddresses, that.ipAddresses);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subjectName, validFrom, validUntil, dnsNames, ipAddresses);
    }

    @Override
    public String toString() {
        return "CertInfo{"
                + "subjectName=" + subjectName
                + ", validFrom=" + validFrom
                + ", validUntil=" + validUntil
                + ", dnsNames=" + dnsNames
                + ", ipAddresses=" + ipAddresses
                + '}';
    }

    public static final class Builder {
        private SubjectName subjectName;
        private Instant validFrom;
        private Instant validUntil;
        private final List<String> dnsNames = new ArrayList<>();
        private final List<String> ipAddresses = new ArrayList<>();

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

        public CertInfo build() {
            return new CertInfo(this);
        }
    }
}
