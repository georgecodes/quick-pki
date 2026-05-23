package com.elevenware.quickpki;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.util.Objects;

/**
 * A single entry in the X.509 {@code qCStatements} extension (RFC 3739
 * §3.2.6). A QCStatement is an OID with an optional ASN.1 payload whose
 * structure is defined per-OID. Multiple statements form the extension value.
 *
 * <p>Held as an opaque {@link ASN1Encodable} so callers can carry both the
 * payload-less statements (eg. {@code id-etsi-qcs-QcCompliance}) and the
 * structured ones (eg. {@code id-etsi-qcs-QcType}, the PSD2 qcStatement)
 * through the same type. Convenience constructors for the standard ETSI and
 * PSD2 statements live on {@link EuQualified}.
 */
public final class QcStatement {

    private final ASN1ObjectIdentifier statementId;
    private final ASN1Encodable statementInfo;

    /**
     * A QCStatement with no statementInfo payload. Use for the boolean-style
     * statements that signal compliance by their presence alone (eg.
     * {@code id-etsi-qcs-QcCompliance}, {@code id-etsi-qcs-QcSSCD}).
     */
    public QcStatement(ASN1ObjectIdentifier statementId) {
        this(statementId, null);
    }

    /**
     * A QCStatement with a structured statementInfo payload. The payload's
     * ASN.1 shape is fixed by the statementId per RFC 3739 / ETSI EN 319 412-5
     * / ETSI TS 119 495.
     */
    public QcStatement(ASN1ObjectIdentifier statementId, ASN1Encodable statementInfo) {
        this.statementId = Objects.requireNonNull(statementId, "statementId must not be null");
        this.statementInfo = statementInfo;
    }

    public ASN1ObjectIdentifier statementId() {
        return statementId;
    }

    /** {@code null} for the payload-less statements. */
    public ASN1Encodable statementInfo() {
        return statementInfo;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof QcStatement that)) return false;
        return statementId.equals(that.statementId)
                && Objects.equals(statementInfo, that.statementInfo);
    }

    @Override
    public int hashCode() {
        return Objects.hash(statementId, statementInfo);
    }

    @Override
    public String toString() {
        return "QcStatement{" + statementId.getId()
                + (statementInfo == null ? "" : ", info=" + statementInfo)
                + '}';
    }
}
