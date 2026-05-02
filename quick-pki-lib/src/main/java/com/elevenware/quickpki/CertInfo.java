package com.elevenware.quickpki;

import java.time.Instant;
import java.util.Objects;

public final class CertInfo {

    private final SubjectName subjectName;
    private final Instant validFrom;
    private final Instant validUntil;

    private CertInfo(Builder builder) {
        this.subjectName = builder.subjectName;
        this.validFrom = builder.validFrom;
        this.validUntil = builder.validUntil;
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CertInfo that)) return false;
        return Objects.equals(subjectName, that.subjectName)
                && Objects.equals(validFrom, that.validFrom)
                && Objects.equals(validUntil, that.validUntil);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subjectName, validFrom, validUntil);
    }

    @Override
    public String toString() {
        return "CertInfo{"
                + "subjectName=" + subjectName
                + ", validFrom=" + validFrom
                + ", validUntil=" + validUntil
                + '}';
    }

    public static final class Builder {
        private SubjectName subjectName;
        private Instant validFrom;
        private Instant validUntil;

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

        public CertInfo build() {
            return new CertInfo(this);
        }
    }
}
