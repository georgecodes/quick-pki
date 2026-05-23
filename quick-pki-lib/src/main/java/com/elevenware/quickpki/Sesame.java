package com.elevenware.quickpki;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Convenience builders for the Sesame Open Source transport (OS_TRANSPORT)
 * and signing (OS_SIGNING) certificate profiles. Each builder collects the
 * subject DN, the participant / software-statement URI SANs, and the Sesame
 * policy OID the leaf must carry, then produces either a {@link CertInfo}
 * (ready to hand to {@link QuickPki#issueCertificate(CertInfo)}) or a signed
 * PKCS#10 CSR.
 *
 * <p>The builders attach the standard Sesame policy OID by default
 * ({@link #OID_OS_TRANSPORT_POLICY} for transport,
 * {@link #OID_OS_SIGNING_POLICY} for signing). The OS_SIGNING profile leaves
 * the ExtendedKeyUsage OID unset - the spec mandates an ecosystem-specific
 * private signing EKU OID, which the caller must supply via
 * {@link OsSigningBuilder#extendedKeyUsageOid(String)}.
 *
 * <p>No validation runs in this class: the spec compliance check happens
 * inside {@link QuickPki} at issuance time, so a builder will happily produce
 * a partially-populated CertInfo or CSR. That mirrors {@link OpenFinanceBrasil}
 * / {@link EuQualified} and lets ACME-style flows assemble a CSR client-side
 * and let the issuing CA reject anything non-compliant with a single,
 * consistent error path.
 *
 * <p>If you already have a fully-populated {@link SubjectName}, the
 * {@link #osTransportCertInfo(SubjectName)} /
 * {@link #osSigningCertInfo(SubjectName)} factories return a
 * {@link CertInfo.Builder} pre-set with the right profile and the standard
 * Sesame policy OID so you can layer your own URI SAN entries on top
 * without going through the fluent builders below.
 */
public final class Sesame {

    /**
     * Sesame Open Source transport (OS_TRANSPORT) policy OID. Carried in the
     * leaf's {@code certificatePolicies} extension; mandatory for compliance.
     */
    public static final String OID_OS_TRANSPORT_POLICY = "1.3.6.1.4.1.19273.1.1";

    /**
     * Sesame Open Source signing (OS_SIGNING) policy OID. Carried in the
     * leaf's {@code certificatePolicies} extension; mandatory for compliance.
     */
    public static final String OID_OS_SIGNING_POLICY = "1.3.6.1.4.1.19273.1.2";

    private Sesame() {}

    /** Starts an OS_TRANSPORT (mTLS client) certificate builder. */
    public static OsTransportBuilder osTransport() {
        return new OsTransportBuilder();
    }

    /** Starts an OS_SIGNING (payload signing) certificate builder. */
    public static OsSigningBuilder osSigning() {
        return new OsSigningBuilder();
    }

    /**
     * Returns a {@link CertInfo.Builder} with the OS_TRANSPORT profile
     * pre-selected, the supplied SubjectName attached, and the standard
     * Sesame transport policy OID populated in certificatePolicies. The
     * caller is responsible for adding the required DNS and URI SAN entries.
     */
    public static CertInfo.Builder osTransportCertInfo(SubjectName subjectName) {
        Objects.requireNonNull(subjectName, "subjectName must not be null");
        return CertInfo.builder()
                .profile(CertificateProfile.OS_TRANSPORT)
                .subjectName(subjectName)
                .certificatePolicy(OID_OS_TRANSPORT_POLICY);
    }

    /**
     * Returns a {@link CertInfo.Builder} with the OS_SIGNING profile
     * pre-selected, the supplied SubjectName attached, and the standard
     * Sesame signing policy OID populated in certificatePolicies. The caller
     * is responsible for adding the required URI SAN entries and the
     * ecosystem-specific signing EKU OID.
     */
    public static CertInfo.Builder osSigningCertInfo(SubjectName subjectName) {
        Objects.requireNonNull(subjectName, "subjectName must not be null");
        return CertInfo.builder()
                .profile(CertificateProfile.OS_SIGNING)
                .subjectName(subjectName)
                .certificatePolicy(OID_OS_SIGNING_POLICY);
    }

    // --------------------------------------------------------------------
    // OS_TRANSPORT builder
    // --------------------------------------------------------------------

    /**
     * Fluent builder for the OS_TRANSPORT subject, DNS / URI SAN entries,
     * and certificatePolicies. The Sesame transport policy OID is added by
     * default; calling {@link #omitDefaultPolicy()} drops it for tests that
     * want to exercise the issuance-time validator.
     */
    public static final class OsTransportBuilder {
        private String commonName;
        private String country;
        private String organization;
        private final List<String> organizationUnits = new ArrayList<>();
        private final List<String> dnsNames = new ArrayList<>();
        private final List<String> uris = new ArrayList<>();
        private final List<String> extraPolicies = new ArrayList<>();
        private boolean emitDefaultPolicy = true;

        private OsTransportBuilder() {}

        /** Subject commonName; typically the transport hostname. */
        public OsTransportBuilder commonName(String commonName) {
            this.commonName = commonName;
            return this;
        }

        /** Two-letter ISO 3166-1 country code. */
        public OsTransportBuilder country(String country) {
            this.country = country;
            return this;
        }

        public OsTransportBuilder organization(String organization) {
            this.organization = organization;
            return this;
        }

        public OsTransportBuilder organizationUnit(String organizationUnit) {
            this.organizationUnits.add(Objects.requireNonNull(organizationUnit,
                    "organizationUnit must not be null"));
            return this;
        }

        /** Adds a DNS subjectAltName. OS_TRANSPORT requires at least one. */
        public OsTransportBuilder dnsName(String dnsName) {
            this.dnsNames.add(Objects.requireNonNull(dnsName, "dnsName must not be null"));
            return this;
        }

        /**
         * Adds a URI subjectAltName. OS_TRANSPORT carries the participant
         * URN and the software-statement URN here (eg.
         * {@code urn:odtf:finance:gb:fca:participant:123456}).
         */
        public OsTransportBuilder uri(String uri) {
            this.uris.add(Objects.requireNonNull(uri, "uri must not be null"));
            return this;
        }

        /** Adds an additional policy OID alongside the Sesame transport policy. */
        public OsTransportBuilder certificatePolicy(String policyOid) {
            this.extraPolicies.add(Objects.requireNonNull(policyOid,
                    "policyOid must not be null"));
            return this;
        }

        /**
         * Drops the default Sesame transport policy OID. Intended for tests
         * that want the validator to reject a non-compliant transport cert;
         * production callers should not use this.
         */
        public OsTransportBuilder omitDefaultPolicy() {
            this.emitDefaultPolicy = false;
            return this;
        }

        public SubjectName subjectName() {
            SubjectName.Builder builder = SubjectName.builder()
                    .country(country)
                    .organization(organization)
                    .commonName(commonName);
            for (String ou : organizationUnits) {
                builder.addOrganizationUnit(ou);
            }
            return builder.build();
        }

        /**
         * Builds a {@link CertInfo.Builder} pre-set with the OS_TRANSPORT
         * profile, the assembled SubjectName, the DNS / URI SAN entries, and
         * the Sesame transport policy OID (plus any extras). Returned as a
         * builder so callers can append validity windows, KeyUsage overrides
         * etc. before {@code build()}.
         */
        public CertInfo.Builder toCertInfo() {
            CertInfo.Builder builder = CertInfo.builder()
                    .profile(CertificateProfile.OS_TRANSPORT)
                    .subjectName(subjectName());
            for (String dnsName : dnsNames) {
                builder.dnsName(dnsName);
            }
            for (String uri : uris) {
                builder.uri(uri);
            }
            if (emitDefaultPolicy) {
                builder.certificatePolicy(OID_OS_TRANSPORT_POLICY);
            }
            for (String policyOid : extraPolicies) {
                builder.certificatePolicy(policyOid);
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

    // --------------------------------------------------------------------
    // OS_SIGNING builder
    // --------------------------------------------------------------------

    /**
     * Fluent builder for the OS_SIGNING subject, URI SAN entries, and
     * certificatePolicies. The Sesame signing policy OID is added by default
     * ({@link #omitDefaultPolicy()} drops it). The ecosystem-specific
     * signing EKU OID must be supplied via
     * {@link #extendedKeyUsageOid(String)}.
     */
    public static final class OsSigningBuilder {
        private String commonName;
        private String country;
        private String organization;
        private final List<String> organizationUnits = new ArrayList<>();
        private final List<String> uris = new ArrayList<>();
        private final List<String> extraPolicies = new ArrayList<>();
        private final List<String> ekuOids = new ArrayList<>();
        private boolean emitDefaultPolicy = true;

        private OsSigningBuilder() {}

        public OsSigningBuilder commonName(String commonName) {
            this.commonName = commonName;
            return this;
        }

        public OsSigningBuilder country(String country) {
            this.country = country;
            return this;
        }

        public OsSigningBuilder organization(String organization) {
            this.organization = organization;
            return this;
        }

        public OsSigningBuilder organizationUnit(String organizationUnit) {
            this.organizationUnits.add(Objects.requireNonNull(organizationUnit,
                    "organizationUnit must not be null"));
            return this;
        }

        /**
         * Adds a URI subjectAltName. OS_SIGNING carries the participant URN
         * and the software-statement URN here.
         */
        public OsSigningBuilder uri(String uri) {
            this.uris.add(Objects.requireNonNull(uri, "uri must not be null"));
            return this;
        }

        /**
         * The ecosystem-specific signing EKU OID. OS_SIGNING certificates do
         * not carry any of the six RFC 5280 standard EKU purposes; the
         * caller must supply the OID their ecosystem mandates.
         */
        public OsSigningBuilder extendedKeyUsageOid(String oid) {
            this.ekuOids.add(Objects.requireNonNull(oid, "oid must not be null"));
            return this;
        }

        /** Adds an additional policy OID alongside the Sesame signing policy. */
        public OsSigningBuilder certificatePolicy(String policyOid) {
            this.extraPolicies.add(Objects.requireNonNull(policyOid,
                    "policyOid must not be null"));
            return this;
        }

        public OsSigningBuilder omitDefaultPolicy() {
            this.emitDefaultPolicy = false;
            return this;
        }

        public SubjectName subjectName() {
            SubjectName.Builder builder = SubjectName.builder()
                    .country(country)
                    .organization(organization)
                    .commonName(commonName);
            for (String ou : organizationUnits) {
                builder.addOrganizationUnit(ou);
            }
            return builder.build();
        }

        public CertInfo.Builder toCertInfo() {
            CertInfo.Builder builder = CertInfo.builder()
                    .profile(CertificateProfile.OS_SIGNING)
                    .subjectName(subjectName());
            for (String uri : uris) {
                builder.uri(uri);
            }
            if (emitDefaultPolicy) {
                builder.certificatePolicy(OID_OS_SIGNING_POLICY);
            }
            for (String policyOid : extraPolicies) {
                builder.certificatePolicy(policyOid);
            }
            for (String ekuOid : ekuOids) {
                builder.extendedKeyUsageOid(ekuOid);
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
