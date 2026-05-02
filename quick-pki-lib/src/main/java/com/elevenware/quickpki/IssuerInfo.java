package com.elevenware.quickpki;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

public final class IssuerInfo {

    private final SubjectName subjectName;
    private final Instant validFrom;
    private final Instant validUntil;
    private final Duration defaultLifespan;

    private IssuerInfo(Builder builder) {
        this.subjectName = builder.subjectName;
        this.validFrom = builder.validFrom != null ? builder.validFrom : Instant.now();
        this.validUntil = builder.validUntil != null ? builder.validUntil
                : Instant.now().plus(1, ChronoUnit.DAYS);
        this.defaultLifespan = builder.defaultLifespan != null ? builder.defaultLifespan
                : Duration.ofDays(1L);
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

    public Duration getDefaultLifespan() {
        return defaultLifespan;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof IssuerInfo that)) return false;
        return Objects.equals(subjectName, that.subjectName)
                && Objects.equals(validFrom, that.validFrom)
                && Objects.equals(validUntil, that.validUntil)
                && Objects.equals(defaultLifespan, that.defaultLifespan);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subjectName, validFrom, validUntil, defaultLifespan);
    }

    @Override
    public String toString() {
        return "IssuerInfo{"
                + "subjectName=" + subjectName
                + ", validFrom=" + validFrom
                + ", validUntil=" + validUntil
                + ", defaultLifespan=" + defaultLifespan
                + '}';
    }

    public static final class Builder {
        private SubjectName subjectName;
        private Instant validFrom;
        private Instant validUntil;
        private Duration defaultLifespan;

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

        public Builder defaultLifespan(Duration defaultLifespan) {
            this.defaultLifespan = defaultLifespan;
            return this;
        }

        public IssuerInfo build() {
            return new IssuerInfo(this);
        }
    }
}
