package com.elevenware.quickpki;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Convenience builders for the Open Finance Brasil BRCAC (transport) and
 * BRSEAL (signing) certificate profiles. Each builder collects the subject
 * attributes and SAN entries mandated by the spec, then produces either a
 * {@link CertInfo} (ready to hand to {@link QuickPki#issueCertificate(CertInfo)})
 * or a signed PKCS#10 CSR.
 *
 * <p>The builders default {@code country} / {@code jurisdictionCountry} to
 * {@code "BR"} and {@code organization} (on BRSEAL) to {@code "ICP-Brasil"},
 * but every field can be overridden so consumers running test fixtures
 * against alternative trust anchors can still drive the helpers.
 *
 * <p>No validation runs in this class: the spec compliance check happens
 * inside {@link QuickPki} at issuance time, so a builder will happily produce
 * a partially-populated CertInfo or CSR. That lets ACME-style flows assemble
 * a CSR client-side and let the issuing CA reject anything non-compliant
 * with a single, consistent error path.
 *
 * <p>If you already have a fully-populated {@link SubjectName}, the
 * {@link #brcacCertInfo(SubjectName)} / {@link #brsealCertInfo(SubjectName)}
 * factories return a {@link CertInfo.Builder} pre-set with the right profile
 * so you can layer your own SAN entries on top without going through the
 * fluent builders below.
 */
public final class OpenFinanceBrasil {

    /** ICP-Brasil otherName OID for the responsible person's name. */
    public static final String OID_RESPONSIBLE_PERSON_NAME = "2.16.76.1.3.2";
    /** ICP-Brasil otherName OID for the company's CNPJ. */
    public static final String OID_COMPANY_CNPJ = "2.16.76.1.3.3";
    /**
     * ICP-Brasil otherName OID for the responsible person's identifying data
     * (concatenated birth-date, CPF, PIS-PASEP and RG, 21 characters).
     */
    public static final String OID_RESPONSIBLE_PERSON_DATA = "2.16.76.1.3.4";
    /** ICP-Brasil otherName OID for the company's CEI registration. */
    public static final String OID_COMPANY_CEI = "2.16.76.1.3.7";

    private OpenFinanceBrasil() {}

    /**
     * Starts a BRCAC (transport / mTLS client) certificate builder.
     */
    public static BrcacBuilder brcac() {
        return new BrcacBuilder();
    }

    /**
     * Starts a BRSEAL (message signing) certificate builder.
     */
    public static BrsealBuilder brseal() {
        return new BrsealBuilder();
    }

    /**
     * Returns a {@link CertInfo.Builder} with the BRCAC profile pre-selected
     * and the supplied SubjectName attached. The caller is responsible for
     * adding the required DNS SAN entry / entries.
     */
    public static CertInfo.Builder brcacCertInfo(SubjectName subjectName) {
        Objects.requireNonNull(subjectName, "subjectName must not be null");
        return CertInfo.builder()
                .profile(CertificateProfile.BRCAC)
                .subjectName(subjectName);
    }

    /**
     * Returns a {@link CertInfo.Builder} with the BRSEAL profile pre-selected
     * and the supplied SubjectName attached. The caller is responsible for
     * adding the four required ICP-Brasil otherName SAN entries.
     */
    public static CertInfo.Builder brsealCertInfo(SubjectName subjectName) {
        Objects.requireNonNull(subjectName, "subjectName must not be null");
        return CertInfo.builder()
                .profile(CertificateProfile.BRSEAL)
                .subjectName(subjectName);
    }

    /**
     * Fluent builder for the BRCAC transport-certificate subject and SAN
     * entries. Defaults: {@code country} and {@code jurisdictionCountry} are
     * preset to {@code "BR"}.
     */
    public static final class BrcacBuilder {
        private String commonName;
        private String businessCategory;
        private String jurisdictionCountry = "BR";
        private String serialNumber;
        private String country = "BR";
        private String organization;
        private String stateOrProvince;
        private String locality;
        private String organizationIdentifier;
        private String userId;
        private final List<String> dnsNames = new ArrayList<>();

        private BrcacBuilder() {}

        /** Subject commonName; typically the transport hostname. */
        public BrcacBuilder commonName(String commonName) {
            this.commonName = commonName;
            return this;
        }

        /**
         * EV-style businessCategory; Open Finance Brasil accepts
         * {@code "Private Organization"}, {@code "Government Entity"},
         * {@code "Business Entity"} or {@code "Non-Commercial Entity"}.
         */
        public BrcacBuilder businessCategory(String businessCategory) {
            this.businessCategory = businessCategory;
            return this;
        }

        /** Jurisdiction-of-incorporation country; defaults to {@code "BR"}. */
        public BrcacBuilder jurisdictionCountry(String jurisdictionCountry) {
            this.jurisdictionCountry = jurisdictionCountry;
            return this;
        }

        /** Subject serialNumber RDN; Open Finance carries the company CNPJ. */
        public BrcacBuilder serialNumber(String serialNumber) {
            this.serialNumber = serialNumber;
            return this;
        }

        /** Subject country; defaults to {@code "BR"}. */
        public BrcacBuilder country(String country) {
            this.country = country;
            return this;
        }

        public BrcacBuilder organization(String organization) {
            this.organization = organization;
            return this;
        }

        public BrcacBuilder stateOrProvince(String stateOrProvince) {
            this.stateOrProvince = stateOrProvince;
            return this;
        }

        public BrcacBuilder locality(String locality) {
            this.locality = locality;
            return this;
        }

        /**
         * organizationIdentifier RDN; Open Finance Brasil expects the
         * participant code prefixed with {@code "OFBBR-"}.
         */
        public BrcacBuilder organizationIdentifier(String organizationIdentifier) {
            this.organizationIdentifier = organizationIdentifier;
            return this;
        }

        /**
         * UID RDN; Open Finance Brasil carries the software-statement
         * identifier here.
         */
        public BrcacBuilder userId(String userId) {
            this.userId = userId;
            return this;
        }

        /**
         * Adds a DNS subjectAltName. BRCAC requires at least one.
         */
        public BrcacBuilder dnsName(String dnsName) {
            this.dnsNames.add(Objects.requireNonNull(dnsName, "dnsName must not be null"));
            return this;
        }

        /** Builds a {@link SubjectName} from the collected RDN values. */
        public SubjectName subjectName() {
            return SubjectName.builder()
                    .businessCategory(businessCategory)
                    .jurisdictionCountry(jurisdictionCountry)
                    .serialNumber(serialNumber)
                    .country(country)
                    .organization(organization)
                    .stateOrProvince(stateOrProvince)
                    .locality(locality)
                    .organizationIdentifier(organizationIdentifier)
                    .userId(userId)
                    .commonName(commonName)
                    .build();
        }

        /**
         * Builds a {@link CertInfo.Builder} pre-set with the BRCAC profile,
         * the assembled SubjectName and any DNS SAN entries. Returned as a
         * builder so callers can append validity windows, KeyUsage overrides
         * etc. before {@code build()}.
         */
        public CertInfo.Builder toCertInfo() {
            CertInfo.Builder builder = brcacCertInfo(subjectName());
            for (String dnsName : dnsNames) {
                builder.dnsName(dnsName);
            }
            return builder;
        }

        /** Signs a PKCS#10 CSR with the supplied key pair. */
        public PKCS10CertificationRequest buildCsr(KeyPair keyPair) {
            return Csr.create(toCertInfo().build(), keyPair);
        }

        /** Convenience: {@link #buildCsr(KeyPair)} then {@link Csr#toPem}. */
        public String buildCsrPem(KeyPair keyPair) {
            return Csr.toPem(buildCsr(keyPair));
        }
    }

    /**
     * Fluent builder for the BRSEAL signing-certificate subject and SAN
     * entries. Defaults: {@code country} is preset to {@code "BR"} and
     * {@code organization} to {@code "ICP-Brasil"}.
     */
    public static final class BrsealBuilder {
        private String commonName;
        private String userId;
        private String country = "BR";
        private String organization = "ICP-Brasil";
        private final List<String> organizationUnits = new ArrayList<>();
        private String responsiblePersonName;
        private String companyCnpj;
        private String responsiblePersonData;
        private String companyCei;

        private BrsealBuilder() {}

        public BrsealBuilder commonName(String commonName) {
            this.commonName = commonName;
            return this;
        }

        /**
         * UID RDN; Open Finance Brasil expects the participant code prefixed
         * with {@code "OFBBR-"}.
         */
        public BrsealBuilder userId(String userId) {
            this.userId = userId;
            return this;
        }

        /** Defaults to {@code "BR"}; override only when reproducing a test fixture. */
        public BrsealBuilder country(String country) {
            this.country = country;
            return this;
        }

        /** Defaults to {@code "ICP-Brasil"}; override only when reproducing a test fixture. */
        public BrsealBuilder organization(String organization) {
            this.organization = organization;
            return this;
        }

        /**
         * Appends an organizationUnit RDN. BRSEAL requires three: typically
         * the CA short name, the company CNPJ and the validation method.
         */
        public BrsealBuilder organizationUnit(String organizationUnit) {
            this.organizationUnits.add(Objects.requireNonNull(organizationUnit,
                    "organizationUnit must not be null"));
            return this;
        }

        /** ICP-Brasil otherName 2.16.76.1.3.2: responsible person's name. */
        public BrsealBuilder responsiblePersonName(String name) {
            this.responsiblePersonName = name;
            return this;
        }

        /** ICP-Brasil otherName 2.16.76.1.3.3: company CNPJ. */
        public BrsealBuilder companyCnpj(String cnpj) {
            this.companyCnpj = cnpj;
            return this;
        }

        /**
         * ICP-Brasil otherName 2.16.76.1.3.4: concatenated birth-date, CPF,
         * PIS-PASEP and RG of the responsible person (21 characters).
         */
        public BrsealBuilder responsiblePersonData(String data) {
            this.responsiblePersonData = data;
            return this;
        }

        /** ICP-Brasil otherName 2.16.76.1.3.7: company CEI. */
        public BrsealBuilder companyCei(String cei) {
            this.companyCei = cei;
            return this;
        }

        public SubjectName subjectName() {
            SubjectName.Builder builder = SubjectName.builder()
                    .userId(userId)
                    .country(country)
                    .organization(organization)
                    .commonName(commonName);
            for (String organizationUnit : organizationUnits) {
                builder.addOrganizationUnit(organizationUnit);
            }
            return builder.build();
        }

        /**
         * Builds a {@link CertInfo.Builder} pre-set with the BRSEAL profile,
         * the assembled SubjectName and any ICP-Brasil otherName SAN entries
         * supplied. Returned as a builder so callers can append validity
         * windows, KeyUsage overrides etc. before {@code build()}.
         */
        public CertInfo.Builder toCertInfo() {
            CertInfo.Builder builder = brsealCertInfo(subjectName());
            if (responsiblePersonName != null) {
                builder.otherName(OID_RESPONSIBLE_PERSON_NAME, responsiblePersonName);
            }
            if (companyCnpj != null) {
                builder.otherName(OID_COMPANY_CNPJ, companyCnpj);
            }
            if (responsiblePersonData != null) {
                builder.otherName(OID_RESPONSIBLE_PERSON_DATA, responsiblePersonData);
            }
            if (companyCei != null) {
                builder.otherName(OID_COMPANY_CEI, companyCei);
            }
            return builder;
        }

        public PKCS10CertificationRequest buildCsr(KeyPair keyPair) {
            return Csr.create(toCertInfo().build(), keyPair);
        }

        public String buildCsrPem(KeyPair keyPair) {
            return Csr.toPem(buildCsr(keyPair));
        }
    }
}
