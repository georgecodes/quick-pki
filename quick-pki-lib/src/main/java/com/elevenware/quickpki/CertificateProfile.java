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
