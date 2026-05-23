package com.elevenware.quickpki;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class SubjectName {

    private final String commonName;
    private final String country;
    private final String organization;
    private final List<String> organizationUnits;
    private final String dnQualifier;
    private final String locality;
    private final String stateOrProvince;
    private final String organizationIdentifier;
    private final String businessCategory;
    private final String jurisdictionCountry;
    private final String serialNumber;
    private final String userId;

    private SubjectName(Builder builder) {
        this.commonName = builder.commonName;
        this.country = builder.country;
        this.organization = builder.organization;
        this.organizationUnits = List.copyOf(builder.organizationUnits);
        this.dnQualifier = builder.dnQualifier;
        this.locality = builder.locality;
        this.stateOrProvince = builder.stateOrProvince;
        this.organizationIdentifier = builder.organizationIdentifier;
        this.businessCategory = builder.businessCategory;
        this.jurisdictionCountry = builder.jurisdictionCountry;
        this.serialNumber = builder.serialNumber;
        this.userId = builder.userId;
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
        return organizationUnits.isEmpty() ? null : organizationUnits.get(0);
    }

    public List<String> getOrganizationUnits() {
        return organizationUnits;
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

    // organizationIdentifier (OID 2.5.4.97). Open Finance Brasil carries the
    // participant code here, formatted as "OFBBR-<code>".
    public String getOrganizationIdentifier() {
        return organizationIdentifier;
    }

    // businessCategory (OID 2.5.4.15). Open Finance Brasil expects one of
    // "Private Organization", "Government Entity", "Business Entity" or
    // "Non-Commercial Entity".
    public String getBusinessCategory() {
        return businessCategory;
    }

    // jurisdictionCountryName (OID 1.3.6.1.4.1.311.60.2.1.3), the EV-style
    // jurisdiction-of-incorporation country. Open Finance Brasil uses "BR".
    public String getJurisdictionCountry() {
        return jurisdictionCountry;
    }

    // serialNumber (OID 2.5.4.5) RDN - not the certificate serial number.
    // Open Finance Brasil carries the organisation CNPJ here.
    public String getSerialNumber() {
        return serialNumber;
    }

    // userId / UID (OID 0.9.2342.19200300.100.1.1).
    public String getUserId() {
        return userId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SubjectName that)) return false;
        return Objects.equals(commonName, that.commonName)
                && Objects.equals(country, that.country)
                && Objects.equals(organization, that.organization)
                && Objects.equals(organizationUnits, that.organizationUnits)
                && Objects.equals(dnQualifier, that.dnQualifier)
                && Objects.equals(locality, that.locality)
                && Objects.equals(stateOrProvince, that.stateOrProvince)
                && Objects.equals(organizationIdentifier, that.organizationIdentifier)
                && Objects.equals(businessCategory, that.businessCategory)
                && Objects.equals(jurisdictionCountry, that.jurisdictionCountry)
                && Objects.equals(serialNumber, that.serialNumber)
                && Objects.equals(userId, that.userId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(commonName, country, organization, organizationUnits,
                dnQualifier, locality, stateOrProvince, organizationIdentifier,
                businessCategory, jurisdictionCountry, serialNumber, userId);
    }

    @Override
    public String toString() {
        return "SubjectName{"
                + "commonName=" + commonName
                + ", country=" + country
                + ", organization=" + organization
                + ", organizationUnits=" + organizationUnits
                + ", dnQualifier=" + dnQualifier
                + ", locality=" + locality
                + ", stateOrProvince=" + stateOrProvince
                + ", organizationIdentifier=" + organizationIdentifier
                + ", businessCategory=" + businessCategory
                + ", jurisdictionCountry=" + jurisdictionCountry
                + ", serialNumber=" + serialNumber
                + ", userId=" + userId
                + '}';
    }

    public static final class Builder {
        private String commonName;
        private String country;
        private String organization;
        private final List<String> organizationUnits = new ArrayList<>();
        private String dnQualifier;
        private String locality;
        private String stateOrProvince;
        private String organizationIdentifier;
        private String businessCategory;
        private String jurisdictionCountry;
        private String serialNumber;
        private String userId;

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
            this.organizationUnits.clear();
            if (organizationUnit != null) {
                this.organizationUnits.add(organizationUnit);
            }
            return this;
        }

        public Builder addOrganizationUnit(String organizationUnit) {
            this.organizationUnits.add(Objects.requireNonNull(organizationUnit,
                    "organizationUnit must not be null"));
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

        public Builder organizationIdentifier(String organizationIdentifier) {
            this.organizationIdentifier = organizationIdentifier;
            return this;
        }

        public Builder businessCategory(String businessCategory) {
            this.businessCategory = businessCategory;
            return this;
        }

        public Builder jurisdictionCountry(String jurisdictionCountry) {
            this.jurisdictionCountry = jurisdictionCountry;
            return this;
        }

        public Builder serialNumber(String serialNumber) {
            this.serialNumber = serialNumber;
            return this;
        }

        public Builder userId(String userId) {
            this.userId = userId;
            return this;
        }

        public SubjectName build() {
            return new SubjectName(this);
        }
    }
}
