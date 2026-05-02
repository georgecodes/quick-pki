package com.elevenware.quickpki;

import java.util.Objects;

public final class SubjectName {

    private final String commonName;
    private final String country;
    private final String organization;
    private final String organizationUnit;
    private final String dnQualifier;
    private final String locality;
    private final String stateOrProvince;

    private SubjectName(Builder builder) {
        this.commonName = builder.commonName;
        this.country = builder.country;
        this.organization = builder.organization;
        this.organizationUnit = builder.organizationUnit;
        this.dnQualifier = builder.dnQualifier;
        this.locality = builder.locality;
        this.stateOrProvince = builder.stateOrProvince;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getCommonName() {
        return commonName;
    }

    public String getCountry() {
        return country;
    }

    public String getOrganization() {
        return organization;
    }

    public String getOrganizationUnit() {
        return organizationUnit;
    }

    public String getDnQualifier() {
        return dnQualifier;
    }

    public String getLocality() {
        return locality;
    }

    public String getStateOrProvince() {
        return stateOrProvince;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SubjectName that)) return false;
        return Objects.equals(commonName, that.commonName)
                && Objects.equals(country, that.country)
                && Objects.equals(organization, that.organization)
                && Objects.equals(organizationUnit, that.organizationUnit)
                && Objects.equals(dnQualifier, that.dnQualifier)
                && Objects.equals(locality, that.locality)
                && Objects.equals(stateOrProvince, that.stateOrProvince);
    }

    @Override
    public int hashCode() {
        return Objects.hash(commonName, country, organization, organizationUnit,
                dnQualifier, locality, stateOrProvince);
    }

    @Override
    public String toString() {
        return "SubjectName{"
                + "commonName=" + commonName
                + ", country=" + country
                + ", organization=" + organization
                + ", organizationUnit=" + organizationUnit
                + ", dnQualifier=" + dnQualifier
                + ", locality=" + locality
                + ", stateOrProvince=" + stateOrProvince
                + '}';
    }

    public static final class Builder {
        private String commonName;
        private String country;
        private String organization;
        private String organizationUnit;
        private String dnQualifier;
        private String locality;
        private String stateOrProvince;

        private Builder() {
        }

        public Builder commonName(String commonName) {
            this.commonName = commonName;
            return this;
        }

        public Builder country(String country) {
            this.country = country;
            return this;
        }

        public Builder organization(String organization) {
            this.organization = organization;
            return this;
        }

        public Builder organizationUnit(String organizationUnit) {
            this.organizationUnit = organizationUnit;
            return this;
        }

        public Builder dnQualifier(String dnQualifier) {
            this.dnQualifier = dnQualifier;
            return this;
        }

        public Builder locality(String locality) {
            this.locality = locality;
            return this;
        }

        public Builder stateOrProvince(String stateOrProvince) {
            this.stateOrProvince = stateOrProvince;
            return this;
        }

        public SubjectName build() {
            return new SubjectName(this);
        }
    }
}
