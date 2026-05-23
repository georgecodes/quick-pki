package com.elevenware.quickpki;

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A named bundle of leaf-certificate policy - the KeyUsage and ExtendedKeyUsage
 * a certificate should carry. Selecting a profile on a {@link CertInfo} lets a
 * caller issue a certificate shaped for a particular use case without spelling
 * out every usage bit by hand.
 *
 * <p>A profile only supplies <em>defaults</em>. Explicit
 * {@link CertInfo.Builder#keyUsage(KeyUsageBit)} /
 * {@link CertInfo.Builder#extendedKeyUsage(ExtendedKeyUsageId)} calls still
 * win, so a profile can be picked as a baseline and then tweaked.
 *
 * <p>{@link #BRCAC} and {@link #BRSEAL} model the transport and signing
 * certificate profiles from the Open Finance Brasil certificate standards.
 * {@link #QWAC} and {@link #QSEAL} model the EU eIDAS / PSD2 Qualified Web
 * Authentication and Qualified Electronic Seal profiles
 * (ETSI EN 319 412-2/-3 and ETSI TS 119 495 for the PSD2 attribute set).
 * {@link #OS_TRANSPORT} and {@link #OS_SIGNING} model the Sesame Open Source
 * transport and signing certificate profiles.
 */
public enum CertificateProfile {

    /**
     * No opinion: KeyUsage is chosen from the leaf's key algorithm and
     * ExtendedKeyUsage defaults to serverAuth + clientAuth. This is the
     * behaviour QuickPki had before profiles existed.
     */
    DEFAULT(null, null),

    /** TLS server: algorithm-default KeyUsage, ExtendedKeyUsage = serverAuth. */
    TLS_SERVER(null, EnumSet.of(ExtendedKeyUsageId.SERVER_AUTH)),

    /** TLS client: algorithm-default KeyUsage, ExtendedKeyUsage = clientAuth. */
    TLS_CLIENT(null, EnumSet.of(ExtendedKeyUsageId.CLIENT_AUTH)),

    /**
     * Open Finance Brasil transport certificate (BRCAC): KeyUsage
     * digitalSignature + keyEncipherment, ExtendedKeyUsage clientAuth. Used for
     * mutual-TLS client authentication between Open Finance participants.
     */
    BRCAC(
            EnumSet.of(KeyUsageBit.DIGITAL_SIGNATURE, KeyUsageBit.KEY_ENCIPHERMENT),
            EnumSet.of(ExtendedKeyUsageId.CLIENT_AUTH)),

    /**
     * Open Finance Brasil signing certificate (BRSEAL): KeyUsage
     * digitalSignature + nonRepudiation, and no ExtendedKeyUsage extension at
     * all. Used to sign message payloads (JWS) between participants.
     */
    BRSEAL(
            EnumSet.of(KeyUsageBit.DIGITAL_SIGNATURE, KeyUsageBit.NON_REPUDIATION),
            EnumSet.noneOf(ExtendedKeyUsageId.class)),

    /**
     * EU Qualified Web Authentication Certificate (QWAC): KeyUsage
     * digitalSignature + keyEncipherment, ExtendedKeyUsage
     * serverAuth + clientAuth. Used by PSPs under PSD2 to identify themselves
     * to ASPSPs and to TPP clients during mutual TLS. Profile compliance also
     * requires the standard ETSI QC statements (QcCompliance + QcType=web);
     * {@link EuQualified#qwac()} emits them by default.
     */
    QWAC(
            EnumSet.of(KeyUsageBit.DIGITAL_SIGNATURE, KeyUsageBit.KEY_ENCIPHERMENT),
            EnumSet.of(ExtendedKeyUsageId.SERVER_AUTH, ExtendedKeyUsageId.CLIENT_AUTH)),

    /**
     * EU Qualified Electronic Seal Certificate (QSEAL): KeyUsage
     * digitalSignature + nonRepudiation, and no ExtendedKeyUsage extension at
     * all. Used to seal message payloads (eg. detached JWS signatures over
     * PSD2 API messages). Profile compliance also requires the standard ETSI
     * QC statements (QcCompliance + QcType=eseal); {@link EuQualified#qseal()}
     * emits them by default.
     */
    QSEAL(
            EnumSet.of(KeyUsageBit.DIGITAL_SIGNATURE, KeyUsageBit.NON_REPUDIATION),
            EnumSet.noneOf(ExtendedKeyUsageId.class)),

    /**
     * Sesame Open Source transport (OS_TRANSPORT) certificate: KeyUsage
     * digitalSignature, ExtendedKeyUsage clientAuth. Used for mutual-TLS
     * client authentication between Sesame participants; carries the
     * participant and software-statement URNs as URI subjectAltName entries
     * and the Sesame transport policy OID in {@code certificatePolicies}.
     * {@link Sesame#osTransport()} populates the standard policy OID by
     * default.
     */
    OS_TRANSPORT(
            EnumSet.of(KeyUsageBit.DIGITAL_SIGNATURE),
            EnumSet.of(ExtendedKeyUsageId.CLIENT_AUTH)),

    /**
     * Sesame Open Source signing (OS_SIGNING) certificate: KeyUsage
     * digitalSignature + nonRepudiation, ExtendedKeyUsage left empty so the
     * caller can supply the ecosystem-specific private signing EKU OID via
     * {@link CertInfo.Builder#extendedKeyUsageOid(String)}. Carries the
     * participant and software-statement URNs as URI subjectAltName entries
     * and the Sesame signing policy OID in {@code certificatePolicies}.
     * {@link Sesame#osSigning()} populates the standard policy OID by
     * default.
     */
    OS_SIGNING(
            EnumSet.of(KeyUsageBit.DIGITAL_SIGNATURE, KeyUsageBit.NON_REPUDIATION),
            EnumSet.noneOf(ExtendedKeyUsageId.class));

    private final Set<KeyUsageBit> keyUsages;
    private final Set<ExtendedKeyUsageId> extendedKeyUsages;

    CertificateProfile(EnumSet<KeyUsageBit> keyUsages,
                       EnumSet<ExtendedKeyUsageId> extendedKeyUsages) {
        this.keyUsages = keyUsages == null ? null
                : Collections.unmodifiableSet(EnumSet.copyOf(keyUsages));
        this.extendedKeyUsages = extendedKeyUsages == null ? null
                : Collections.unmodifiableSet(EnumSet.copyOf(extendedKeyUsages));
    }

    /**
     * Resolves a profile from its name, case-insensitively. A {@code null} or
     * blank name resolves to {@link #DEFAULT} so callers can treat "no profile
     * supplied" and "DEFAULT profile" identically.
     *
     * @throws IllegalArgumentException if {@code name} matches no profile
     */
    public static CertificateProfile fromName(String name) {
        if (name == null || name.isBlank()) {
            return DEFAULT;
        }
        String trimmed = name.trim();
        for (CertificateProfile profile : values()) {
            if (profile.name().equalsIgnoreCase(trimmed)) {
                return profile;
            }
        }
        throw new IllegalArgumentException("Unknown certificate profile '" + name
                + "'; valid profiles are " + Arrays.stream(values())
                        .map(Enum::name)
                        .collect(Collectors.joining(", ")));
    }

    /**
     * The KeyUsage bits this profile mandates, or {@code null} when the profile
     * leaves KeyUsage to QuickPki's algorithm-aware default.
     */
    public Set<KeyUsageBit> keyUsages() {
        return keyUsages;
    }

    /**
     * The ExtendedKeyUsage purposes this profile mandates. {@code null} means
     * the profile has no opinion (the serverAuth + clientAuth default applies);
     * an empty set means the certificate carries no ExtendedKeyUsage extension
     * at all (eg. {@link #BRSEAL}).
     */
    public Set<ExtendedKeyUsageId> extendedKeyUsages() {
        return extendedKeyUsages;
    }
}
