package com.elevenware.quickpki;

import java.time.Instant;

public class CertInfo {
    private SubjectName subjectName;
    private Instant validFrom;
    private Instant validUntil;

    @java.lang.SuppressWarnings("all")
    CertInfo(final SubjectName subjectName, final Instant validFrom, final Instant validUntil) {
        this.subjectName = subjectName;
        this.validFrom = validFrom;
        this.validUntil = validUntil;
    }


    @java.lang.SuppressWarnings("all")
    public static class CertInfoBuilder {
        @java.lang.SuppressWarnings("all")
        private SubjectName subjectName;
        @java.lang.SuppressWarnings("all")
        private Instant validFrom;
        @java.lang.SuppressWarnings("all")
        private Instant validUntil;

        @java.lang.SuppressWarnings("all")
        CertInfoBuilder() {
        }

        /**
         * @return {@code this}.
         */
        @java.lang.SuppressWarnings("all")
        public CertInfo.CertInfoBuilder subjectName(final SubjectName subjectName) {
            this.subjectName = subjectName;
            return this;
        }

        /**
         * @return {@code this}.
         */
        @java.lang.SuppressWarnings("all")
        public CertInfo.CertInfoBuilder validFrom(final Instant validFrom) {
            this.validFrom = validFrom;
            return this;
        }

        /**
         * @return {@code this}.
         */
        @java.lang.SuppressWarnings("all")
        public CertInfo.CertInfoBuilder validUntil(final Instant validUntil) {
            this.validUntil = validUntil;
            return this;
        }

        @java.lang.SuppressWarnings("all")
        public CertInfo build() {
            return new CertInfo(this.subjectName, this.validFrom, this.validUntil);
        }

        @java.lang.Override
        @java.lang.SuppressWarnings("all")
        public java.lang.String toString() {
            return "CertInfo.CertInfoBuilder(subjectName=" + this.subjectName + ", validFrom=" + this.validFrom + ", validUntil=" + this.validUntil + ")";
        }
    }

    @java.lang.SuppressWarnings("all")
    public static CertInfo.CertInfoBuilder builder() {
        return new CertInfo.CertInfoBuilder();
    }

    @java.lang.SuppressWarnings("all")
    public SubjectName getSubjectName() {
        return this.subjectName;
    }

    @java.lang.SuppressWarnings("all")
    public Instant getValidFrom() {
        return this.validFrom;
    }

    @java.lang.SuppressWarnings("all")
    public Instant getValidUntil() {
        return this.validUntil;
    }

    @java.lang.SuppressWarnings("all")
    public void setSubjectName(final SubjectName subjectName) {
        this.subjectName = subjectName;
    }

    @java.lang.SuppressWarnings("all")
    public void setValidFrom(final Instant validFrom) {
        this.validFrom = validFrom;
    }

    @java.lang.SuppressWarnings("all")
    public void setValidUntil(final Instant validUntil) {
        this.validUntil = validUntil;
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("all")
    public boolean equals(final java.lang.Object o) {
        if (o == this) return true;
        if (!(o instanceof CertInfo)) return false;
        final CertInfo other = (CertInfo) o;
        if (!other.canEqual((java.lang.Object) this)) return false;
        final java.lang.Object this$subjectName = this.getSubjectName();
        final java.lang.Object other$subjectName = other.getSubjectName();
        if (this$subjectName == null ? other$subjectName != null : !this$subjectName.equals(other$subjectName)) return false;
        final java.lang.Object this$validFrom = this.getValidFrom();
        final java.lang.Object other$validFrom = other.getValidFrom();
        if (this$validFrom == null ? other$validFrom != null : !this$validFrom.equals(other$validFrom)) return false;
        final java.lang.Object this$validUntil = this.getValidUntil();
        final java.lang.Object other$validUntil = other.getValidUntil();
        if (this$validUntil == null ? other$validUntil != null : !this$validUntil.equals(other$validUntil)) return false;
        return true;
    }

    @java.lang.SuppressWarnings("all")
    protected boolean canEqual(final java.lang.Object other) {
        return other instanceof CertInfo;
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("all")
    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final java.lang.Object $subjectName = this.getSubjectName();
        result = result * PRIME + ($subjectName == null ? 43 : $subjectName.hashCode());
        final java.lang.Object $validFrom = this.getValidFrom();
        result = result * PRIME + ($validFrom == null ? 43 : $validFrom.hashCode());
        final java.lang.Object $validUntil = this.getValidUntil();
        result = result * PRIME + ($validUntil == null ? 43 : $validUntil.hashCode());
        return result;
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("all")
    public java.lang.String toString() {
        return "CertInfo(subjectName=" + this.getSubjectName() + ", validFrom=" + this.getValidFrom() + ", validUntil=" + this.getValidUntil() + ")";
    }
}

