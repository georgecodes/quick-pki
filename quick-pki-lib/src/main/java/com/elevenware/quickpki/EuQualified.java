package com.elevenware.quickpki;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Convenience builders for the EU eIDAS / PSD2 Qualified Web Authentication
 * (QWAC) and Qualified Electronic Seal (QSEAL) certificate profiles. Each
 * builder collects the subject attributes, SAN entries, and ETSI QC statements
 * mandated by the relevant specs (ETSI EN 319 412-1/-2/-3, ETSI EN 319 412-5
 * for the QC statements, and ETSI TS 119 495 for the PSD2 attribute set), then
 * produces either a {@link CertInfo} (ready to hand to
 * {@link QuickPki#issueCertificate(CertInfo)}) or a signed PKCS#10 CSR.
 *
 * <p>The builders default the QC statements every qualified leaf must carry
 * (QcCompliance + QcType, web or eseal) so a minimal caller only has to supply
 * the subject DN. Optional extras - the PSD2 qcStatement listing the PSP
 * roles + NCA, QcPDS PDS-URL pointers, QcSSCD for QSEAL on a QSCD - are added
 * via the dedicated fluent methods.
 *
 * <p>No validation runs in this class: the spec compliance check happens
 * inside {@link QuickPki} at issuance time, so a builder will happily produce
 * a partially-populated CertInfo or CSR. That mirrors how
 * {@link OpenFinanceBrasil} behaves and lets ACME-style flows assemble a CSR
 * client-side and let the issuing CA reject anything non-compliant with a
 * single, consistent error path.
 *
 * <p>If you already have a fully-populated {@link SubjectName}, the
 * {@link #qwacCertInfo(SubjectName)} / {@link #qsealCertInfo(SubjectName)}
 * factories return a {@link CertInfo.Builder} pre-set with the right profile
 * and the two mandatory QC statements so you can layer your own SAN entries
 * and extra qcStatements on top without going through the fluent builders
 * below.
 */
public final class EuQualified {

    /** {@code id-pe-qcStatements} - the X.509 extension OID (RFC 3739 §3.2.6). */
    public static final String OID_QC_STATEMENTS_EXTENSION = "1.3.6.1.5.5.7.1.3";

    /** {@code id-etsi-qcs-QcCompliance} (ETSI EN 319 412-5 §4.2.1). */
    public static final String OID_QC_COMPLIANCE = "0.4.0.1862.1.1";
    /** {@code id-etsi-qcs-LimitValue} (ETSI EN 319 412-5 §4.3.2). */
    public static final String OID_QC_LIMIT_VALUE = "0.4.0.1862.1.2";
    /** {@code id-etsi-qcs-RetentionPeriod} (ETSI EN 319 412-5 §4.3.3). */
    public static final String OID_QC_RETENTION_PERIOD = "0.4.0.1862.1.3";
    /** {@code id-etsi-qcs-QcSSCD} - private key held on a QSCD (ETSI EN 319 412-5 §4.2.2). */
    public static final String OID_QC_SSCD = "0.4.0.1862.1.4";
    /** {@code id-etsi-qcs-QcPDS} - PKI Disclosure Statement URLs (ETSI EN 319 412-5 §4.3.4). */
    public static final String OID_QC_PDS = "0.4.0.1862.1.5";
    /** {@code id-etsi-qcs-QcType} (ETSI EN 319 412-5 §4.2.3). */
    public static final String OID_QC_TYPE = "0.4.0.1862.1.6";

    /** {@code id-etsi-qct-esign} - QcType value for electronic signatures (natural person). */
    public static final String OID_QC_TYPE_ESIGN = "0.4.0.1862.1.6.1";
    /** {@code id-etsi-qct-eseal} - QcType value for electronic seals (legal person; QSEAL). */
    public static final String OID_QC_TYPE_ESEAL = "0.4.0.1862.1.6.2";
    /** {@code id-etsi-qct-web} - QcType value for web authentication (QWAC). */
    public static final String OID_QC_TYPE_WEB = "0.4.0.1862.1.6.3";

    /** {@code id-etsi-psd2-qcStatement} (ETSI TS 119 495 §5.1). */
    public static final String OID_PSD2_QC_STATEMENT = "0.4.0.19495.2";

    private EuQualified() {}

    /**
     * The four PSD2 PSP roles defined by ETSI TS 119 495 §5.1. The OID is the
     * machine-readable identifier carried in the {@code roleOfPspOid} field
     * of the PSD2 qcStatement; {@link #abbreviation()} is the corresponding
     * fixed string carried in {@code roleOfPspName}.
     */
    public enum Psd2Role {

        /** Account Servicing Payment Service Provider. */
        PSP_AS("0.4.0.19495.1.1", "PSP_AS"),
        /** Payment Initiation Service Provider. */
        PSP_PI("0.4.0.19495.1.2", "PSP_PI"),
        /** Account Information Service Provider. */
        PSP_AI("0.4.0.19495.1.3", "PSP_AI"),
        /** Issuer of card-based payment instruments. */
        PSP_IC("0.4.0.19495.1.4", "PSP_IC");

        private final String oid;
        private final String abbreviation;

        Psd2Role(String oid, String abbreviation) {
            this.oid = oid;
            this.abbreviation = abbreviation;
        }

        public String oid() {
            return oid;
        }

        public String abbreviation() {
            return abbreviation;
        }
    }

    /**
     * A single PDS URL/language pair carried in a {@code QcPDS} qcStatement.
     * The language must be an ISO 639-1 two-letter code (eg. {@code "en"});
     * the URL is rendered as IA5String per ETSI EN 319 412-5.
     */
    public record PdsLocation(String url, String language) {
        public PdsLocation {
            Objects.requireNonNull(url, "url must not be null");
            Objects.requireNonNull(language, "language must not be null");
            if (language.length() != 2) {
                throw new IllegalArgumentException(
                        "PDS language must be a two-letter ISO 639-1 code (got '" + language + "')");
            }
        }
    }

    /** Starts a QWAC (transport / mTLS, server + client auth) certificate builder. */
    public static QwacBuilder qwac() {
        return new QwacBuilder();
    }

    /** Starts a QSEAL (legal-person seal, signs payloads) certificate builder. */
    public static QsealBuilder qseal() {
        return new QsealBuilder();
    }

    /**
     * Returns a {@link CertInfo.Builder} with the QWAC profile pre-selected,
     * the supplied SubjectName attached, and the two mandatory ETSI QC
     * statements (QcCompliance + QcType=web) populated. The caller is
     * responsible for adding the required DNS SAN entry / entries and any
     * additional qcStatements (eg. PSD2, QcPDS) the deployment needs.
     */
    public static CertInfo.Builder qwacCertInfo(SubjectName subjectName) {
        Objects.requireNonNull(subjectName, "subjectName must not be null");
        return CertInfo.builder()
                .profile(CertificateProfile.QWAC)
                .subjectName(subjectName)
                .qcStatement(qcCompliance())
                .qcStatement(qcType(OID_QC_TYPE_WEB));
    }

    /**
     * Returns a {@link CertInfo.Builder} with the QSEAL profile pre-selected,
     * the supplied SubjectName attached, and the two mandatory ETSI QC
     * statements (QcCompliance + QcType=eseal) populated.
     */
    public static CertInfo.Builder qsealCertInfo(SubjectName subjectName) {
        Objects.requireNonNull(subjectName, "subjectName must not be null");
        return CertInfo.builder()
                .profile(CertificateProfile.QSEAL)
                .subjectName(subjectName)
                .qcStatement(qcCompliance())
                .qcStatement(qcType(OID_QC_TYPE_ESEAL));
    }

    /**
     * The {@code id-etsi-qcs-QcCompliance} statement that signals the leaf is
     * a qualified certificate under Regulation (EU) 910/2014 (eIDAS).
     */
    public static QcStatement qcCompliance() {
        return new QcStatement(new ASN1ObjectIdentifier(OID_QC_COMPLIANCE));
    }

    /**
     * The {@code id-etsi-qcs-QcSSCD} statement that signals the corresponding
     * private key is held on a Qualified Signature/Seal Creation Device.
     */
    public static QcStatement qcSSCD() {
        return new QcStatement(new ASN1ObjectIdentifier(OID_QC_SSCD));
    }

    /**
     * A {@code id-etsi-qcs-QcType} statement carrying the supplied QcType
     * value OID. Use {@link #OID_QC_TYPE_WEB} for QWAC, {@link #OID_QC_TYPE_ESEAL}
     * for QSEAL, {@link #OID_QC_TYPE_ESIGN} for natural-person eSign.
     */
    public static QcStatement qcType(String typeOid) {
        Objects.requireNonNull(typeOid, "typeOid must not be null");
        return new QcStatement(
                new ASN1ObjectIdentifier(OID_QC_TYPE),
                new DERSequence(new ASN1ObjectIdentifier(typeOid)));
    }

    /**
     * A {@code id-etsi-qcs-QcPDS} statement listing one or more PKI
     * Disclosure Statement URLs with their language.
     */
    public static QcStatement qcPds(List<PdsLocation> locations) {
        Objects.requireNonNull(locations, "locations must not be null");
        if (locations.isEmpty()) {
            throw new IllegalArgumentException("qcPds requires at least one PdsLocation");
        }
        ASN1Encodable[] entries = new ASN1Encodable[locations.size()];
        for (int i = 0; i < locations.size(); i++) {
            PdsLocation loc = locations.get(i);
            entries[i] = new DERSequence(new ASN1Encodable[] {
                    new DERIA5String(loc.url()),
                    new DERPrintableString(loc.language())
            });
        }
        return new QcStatement(
                new ASN1ObjectIdentifier(OID_QC_PDS),
                new DERSequence(entries));
    }

    /**
     * The {@code id-etsi-psd2-qcStatement} (ETSI TS 119 495 §5.1) carrying
     * the PSP's roles and the supervising NCA's name and ID. PSD2 QWAC and
     * QSEAL certificates issued under eIDAS for PSD2 use must carry this.
     *
     * @throws IllegalArgumentException if {@code roles} is empty
     */
    public static QcStatement psd2QcStatement(Set<Psd2Role> roles, String ncaName, String ncaId) {
        Objects.requireNonNull(roles, "roles must not be null");
        Objects.requireNonNull(ncaName, "ncaName must not be null");
        Objects.requireNonNull(ncaId, "ncaId must not be null");
        if (roles.isEmpty()) {
            throw new IllegalArgumentException("psd2QcStatement requires at least one PSP role");
        }
        // Iteration order is enum-declaration order regardless of how the
        // caller passed the set in, so the encoded payload is deterministic.
        Set<Psd2Role> ordered = new LinkedHashSet<>(Arrays.asList(Psd2Role.values()));
        ordered.retainAll(roles);
        ASN1Encodable[] roleEntries = new ASN1Encodable[ordered.size()];
        int i = 0;
        for (Psd2Role role : ordered) {
            roleEntries[i++] = new DERSequence(new ASN1Encodable[] {
                    new ASN1ObjectIdentifier(role.oid()),
                    new DERUTF8String(role.abbreviation())
            });
        }
        DERSequence rolesSeq = new DERSequence(roleEntries);
        DERSequence payload = new DERSequence(new ASN1Encodable[] {
                rolesSeq,
                new DERUTF8String(ncaName),
                new DERUTF8String(ncaId)
        });
        return new QcStatement(new ASN1ObjectIdentifier(OID_PSD2_QC_STATEMENT), payload);
    }

    /**
     * Formats an {@code organizationIdentifier} RDN value for a PSD2 PSP per
     * ETSI TS 119 495 §5.2.1: {@code PSD{country}-{NCA-Id}-{PSP-Id}}, eg.
     * {@code PSDGB-FCA-123456}. The country must be the two-letter ISO 3166-1
     * code of the supervising authority's country.
     */
    public static String psd2OrganizationIdentifier(String country, String ncaId, String pspId) {
        Objects.requireNonNull(country, "country must not be null");
        Objects.requireNonNull(ncaId, "ncaId must not be null");
        Objects.requireNonNull(pspId, "pspId must not be null");
        if (country.length() != 2) {
            throw new IllegalArgumentException(
                    "country must be a two-letter ISO 3166-1 code (got '" + country + "')");
        }
        return "PSD" + country.toUpperCase(Locale.ROOT) + "-" + ncaId + "-" + pspId;
    }

    // --------------------------------------------------------------------
    // QWAC builder
    // --------------------------------------------------------------------

    /**
     * Fluent builder for the QWAC subject, SAN entries, and qcStatements.
     * The two mandatory ETSI qcStatements (QcCompliance + QcType=web) are
     * added by default; calling {@link #omitDefaultQcStatements()} drops them
     * for tests that want to verify the issuance-time validation.
     */
    public static final class QwacBuilder {
        private String commonName;
        private String country;
        private String stateOrProvince;
        private String locality;
        private String organization;
        private String organizationIdentifier;
        private final List<String> organizationUnits = new ArrayList<>();
        private String serialNumber;
        private final List<String> dnsNames = new ArrayList<>();
        private final List<QcStatement> extraQcStatements = new ArrayList<>();
        private boolean emitDefaultQcStatements = true;

        private QwacBuilder() {}

        /** Subject commonName; typically the transport hostname. */
        public QwacBuilder commonName(String commonName) {
            this.commonName = commonName;
            return this;
        }

        /** Two-letter ISO 3166-1 country code, per ETSI EN 319 412-1 §5.1.2. */
        public QwacBuilder country(String country) {
            this.country = country;
            return this;
        }

        public QwacBuilder stateOrProvince(String stateOrProvince) {
            this.stateOrProvince = stateOrProvince;
            return this;
        }

        public QwacBuilder locality(String locality) {
            this.locality = locality;
            return this;
        }

        /** Subject organizationName; the legal-person registered name. */
        public QwacBuilder organization(String organization) {
            this.organization = organization;
            return this;
        }

        /**
         * Subject organizationIdentifier (OID 2.5.4.97). For PSD2 use
         * {@link #psd2OrganizationIdentifier(String, String, String)} to
         * format it; for non-PSD2 deployments use the LEI/VAT/NTR prefix
         * defined by ETSI EN 319 412-1 §5.1.4.
         */
        public QwacBuilder organizationIdentifier(String organizationIdentifier) {
            this.organizationIdentifier = organizationIdentifier;
            return this;
        }

        public QwacBuilder organizationUnit(String organizationUnit) {
            this.organizationUnits.add(Objects.requireNonNull(organizationUnit,
                    "organizationUnit must not be null"));
            return this;
        }

        public QwacBuilder serialNumber(String serialNumber) {
            this.serialNumber = serialNumber;
            return this;
        }

        /** Adds a DNS subjectAltName. QWAC requires at least one. */
        public QwacBuilder dnsName(String dnsName) {
            this.dnsNames.add(Objects.requireNonNull(dnsName, "dnsName must not be null"));
            return this;
        }

        /**
         * Adds the PSD2 qcStatement to the leaf, listing the PSP's roles and
         * the supervising NCA's name and ID. Required for any QWAC issued in
         * a PSD2 context; ignored by non-PSD2 QWAC profiles.
         */
        public QwacBuilder psd2(Set<Psd2Role> roles, String ncaName, String ncaId) {
            this.extraQcStatements.add(psd2QcStatement(roles, ncaName, ncaId));
            return this;
        }

        /** Adds a {@code QcPDS} qcStatement with the supplied PDS URLs. */
        public QwacBuilder qcPds(List<PdsLocation> locations) {
            this.extraQcStatements.add(EuQualified.qcPds(locations));
            return this;
        }

        /** Adds an arbitrary additional qcStatement (eg. QcLimitValue). */
        public QwacBuilder qcStatement(QcStatement statement) {
            this.extraQcStatements.add(Objects.requireNonNull(statement, "statement must not be null"));
            return this;
        }

        /**
         * Drops the two default qcStatements (QcCompliance + QcType=web).
         * Intended for tests that want the validator to reject a non-compliant
         * QWAC; production callers should not use this.
         */
        public QwacBuilder omitDefaultQcStatements() {
            this.emitDefaultQcStatements = false;
            return this;
        }

        public SubjectName subjectName() {
            SubjectName.Builder builder = SubjectName.builder()
                    .country(country)
                    .stateOrProvince(stateOrProvince)
                    .locality(locality)
                    .organization(organization)
                    .organizationIdentifier(organizationIdentifier)
                    .serialNumber(serialNumber)
                    .commonName(commonName);
            for (String ou : organizationUnits) {
                builder.addOrganizationUnit(ou);
            }
            return builder.build();
        }

        /**
         * Builds a {@link CertInfo.Builder} pre-set with the QWAC profile, the
         * assembled SubjectName, the DNS SAN entries, and every qcStatement
         * (defaults + extras). Returned as a builder so callers can append
         * validity windows, key usage overrides etc. before {@code build()}.
         */
        public CertInfo.Builder toCertInfo() {
            CertInfo.Builder builder = CertInfo.builder()
                    .profile(CertificateProfile.QWAC)
                    .subjectName(subjectName());
            for (String dnsName : dnsNames) {
                builder.dnsName(dnsName);
            }
            if (emitDefaultQcStatements) {
                builder.qcStatement(qcCompliance());
                builder.qcStatement(qcType(OID_QC_TYPE_WEB));
            }
            for (QcStatement statement : extraQcStatements) {
                builder.qcStatement(statement);
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
    // QSEAL builder
    // --------------------------------------------------------------------

    /**
     * Fluent builder for the QSEAL subject and qcStatements. The two
     * mandatory ETSI qcStatements (QcCompliance + QcType=eseal) are added by
     * default; call {@link #omitDefaultQcStatements()} to drop them.
     */
    public static final class QsealBuilder {
        private String commonName;
        private String country;
        private String stateOrProvince;
        private String locality;
        private String organization;
        private String organizationIdentifier;
        private final List<String> organizationUnits = new ArrayList<>();
        private String serialNumber;
        private final List<QcStatement> extraQcStatements = new ArrayList<>();
        private boolean emitDefaultQcStatements = true;
        private boolean qscd;

        private QsealBuilder() {}

        public QsealBuilder commonName(String commonName) {
            this.commonName = commonName;
            return this;
        }

        public QsealBuilder country(String country) {
            this.country = country;
            return this;
        }

        public QsealBuilder stateOrProvince(String stateOrProvince) {
            this.stateOrProvince = stateOrProvince;
            return this;
        }

        public QsealBuilder locality(String locality) {
            this.locality = locality;
            return this;
        }

        public QsealBuilder organization(String organization) {
            this.organization = organization;
            return this;
        }

        public QsealBuilder organizationIdentifier(String organizationIdentifier) {
            this.organizationIdentifier = organizationIdentifier;
            return this;
        }

        public QsealBuilder organizationUnit(String organizationUnit) {
            this.organizationUnits.add(Objects.requireNonNull(organizationUnit,
                    "organizationUnit must not be null"));
            return this;
        }

        public QsealBuilder serialNumber(String serialNumber) {
            this.serialNumber = serialNumber;
            return this;
        }

        /** See {@link QwacBuilder#psd2(Set, String, String)}. */
        public QsealBuilder psd2(Set<Psd2Role> roles, String ncaName, String ncaId) {
            this.extraQcStatements.add(psd2QcStatement(roles, ncaName, ncaId));
            return this;
        }

        public QsealBuilder qcPds(List<PdsLocation> locations) {
            this.extraQcStatements.add(EuQualified.qcPds(locations));
            return this;
        }

        /**
         * Marks the certificate as backed by a Qualified Signature/Seal
         * Creation Device by emitting the {@code QcSSCD} qcStatement.
         */
        public QsealBuilder onQscd() {
            this.qscd = true;
            return this;
        }

        public QsealBuilder qcStatement(QcStatement statement) {
            this.extraQcStatements.add(Objects.requireNonNull(statement, "statement must not be null"));
            return this;
        }

        public QsealBuilder omitDefaultQcStatements() {
            this.emitDefaultQcStatements = false;
            return this;
        }

        public SubjectName subjectName() {
            SubjectName.Builder builder = SubjectName.builder()
                    .country(country)
                    .stateOrProvince(stateOrProvince)
                    .locality(locality)
                    .organization(organization)
                    .organizationIdentifier(organizationIdentifier)
                    .serialNumber(serialNumber)
                    .commonName(commonName);
            for (String ou : organizationUnits) {
                builder.addOrganizationUnit(ou);
            }
            return builder.build();
        }

        public CertInfo.Builder toCertInfo() {
            CertInfo.Builder builder = CertInfo.builder()
                    .profile(CertificateProfile.QSEAL)
                    .subjectName(subjectName());
            if (emitDefaultQcStatements) {
                builder.qcStatement(qcCompliance());
                builder.qcStatement(qcType(OID_QC_TYPE_ESEAL));
            }
            if (qscd) {
                builder.qcStatement(qcSSCD());
            }
            for (QcStatement statement : extraQcStatements) {
                builder.qcStatement(statement);
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

    // Internal helper: expose the unmodifiable set of supported PSP role
    // abbreviations to callers (eg. cert-api) that need to validate inbound
    // role lists.
    static Set<String> roleAbbreviations() {
        Set<String> names = new LinkedHashSet<>();
        for (Psd2Role role : Psd2Role.values()) {
            names.add(role.abbreviation());
        }
        return Collections.unmodifiableSet(names);
    }
}
