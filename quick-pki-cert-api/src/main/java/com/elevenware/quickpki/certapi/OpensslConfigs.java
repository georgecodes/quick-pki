package com.elevenware.quickpki.certapi;

import com.elevenware.quickpki.Csr;
import com.elevenware.quickpki.EuQualified;
import com.elevenware.quickpki.QcStatement;
import com.elevenware.quickpki.Sesame;

import java.io.IOException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Generates openssl {@code req} config files from a caller's structured
 * BRCAC / BRSEAL request. The config bakes the subject DN, the requested
 * extensions, and the SAN entries in, so a caller can produce a compliant
 * CSR locally with:
 *
 * <pre>
 *   openssl req -new -config brcac.cnf -key my-key.pem -out my-csr.pem
 * </pre>
 *
 * <p>The configs use {@code prompt = no}, name every distinguished_name RDN
 * with a stable key (including the EV {@code jurisdictionCountryName} OID
 * that openssl does not have a short name for), and emit RDNs in the order
 * the Open Finance Brasil certificate standard requires.
 */
final class OpensslConfigs {

    private OpensslConfigs() {
    }

    static String forBrcac(BrcacOpensslConfigRequest request) {
        requireNonBlank(request.commonName(), "commonName");
        requireNonBlank(request.businessCategory(), "businessCategory");
        requireNonBlank(request.serialNumber(), "serialNumber");
        requireNonBlank(request.organization(), "organization");
        requireNonBlank(request.stateOrProvince(), "stateOrProvince");
        requireNonBlank(request.locality(), "locality");
        requireNonBlank(request.organizationIdentifier(), "organizationIdentifier");
        requireNonBlank(request.userId(), "userId");
        List<String> dnsNames = request.dnsNames() == null ? List.of() : request.dnsNames();
        if (dnsNames.isEmpty()) {
            throw new CertApiException(400, "invalid_request",
                    "BRCAC requires at least one entry in 'dnsNames'");
        }

        // RDN order matches the BRCAC subject spec; openssl emits RDNs in the
        // order they appear in the [dn] section, so order is significant.
        Map<String, String> dn = new LinkedHashMap<>();
        dn.put("businessCategory", request.businessCategory());
        dn.put("jurisdictionCountryName", defaultIfBlank(request.jurisdictionCountry(), "BR"));
        dn.put("serialNumber", request.serialNumber());
        dn.put("countryName", defaultIfBlank(request.country(), "BR"));
        dn.put("organizationName", request.organization());
        dn.put("stateOrProvinceName", request.stateOrProvince());
        dn.put("localityName", request.locality());
        dn.put("organizationIdentifier", request.organizationIdentifier());
        dn.put("UID", request.userId());
        dn.put("commonName", request.commonName());

        List<String> sanLines = new ArrayList<>();
        int i = 1;
        for (String dnsName : dnsNames) {
            sanLines.add("DNS." + i++ + " = " + dnsName);
        }

        Map<String, String> oids = new LinkedHashMap<>();
        // openssl has no built-in short name for jurisdictionCountryName or
        // organizationIdentifier; declare them in [oids] so they can be used
        // by attribute name in [dn].
        oids.put("jurisdictionCountryName", "1.3.6.1.4.1.311.60.2.1.3");
        oids.put("organizationIdentifier", "2.5.4.97");

        return renderConfig(oids, dn, "ext_brcac", brcacExtensions(sanLines));
    }

    static String forBrseal(BrsealOpensslConfigRequest request) {
        requireNonBlank(request.commonName(), "commonName");
        requireNonBlank(request.userId(), "userId");
        requireNonBlank(request.responsiblePersonName(), "responsiblePersonName");
        requireNonBlank(request.companyCnpj(), "companyCnpj");
        requireNonBlank(request.responsiblePersonData(), "responsiblePersonData");
        requireNonBlank(request.companyCei(), "companyCei");
        List<String> ous = request.organizationUnits() == null ? List.of() : request.organizationUnits();
        if (ous.size() < 3) {
            throw new CertApiException(400, "invalid_request",
                    "BRSEAL requires at least three entries in 'organizationUnits'");
        }

        Map<String, String> dn = new LinkedHashMap<>();
        dn.put("UID", request.userId());
        dn.put("countryName", defaultIfBlank(request.country(), "BR"));
        dn.put("organizationName", defaultIfBlank(request.organization(), "ICP-Brasil"));
        // openssl rejects duplicate keys in [dn]; give each OU a unique key
        // and use the same attribute name on each, which is the documented
        // openssl trick for repeated RDNs.
        int ouIndex = 0;
        for (String ou : ous) {
            dn.put("0.organizationalUnitName." + ouIndex++, ou);
        }
        dn.put("commonName", request.commonName());

        // ICP-Brasil otherName payloads are PrintableString wrapped in a
        // DERTaggedObject(0). openssl's otherName syntax is OID;type:value,
        // and FORMAT:UTF8 is the closest type for the names that aren't
        // strictly PrintableString-safe; PRINTABLE:value works for the
        // PrintableString case.
        List<String> sanLines = new ArrayList<>();
        sanLines.add("otherName.0 = 2.16.76.1.3.2;UTF8:" + request.responsiblePersonName());
        sanLines.add("otherName.1 = 2.16.76.1.3.3;UTF8:" + request.companyCnpj());
        sanLines.add("otherName.2 = 2.16.76.1.3.4;UTF8:" + request.responsiblePersonData());
        sanLines.add("otherName.3 = 2.16.76.1.3.7;UTF8:" + request.companyCei());

        Map<String, String> oids = new LinkedHashMap<>();
        oids.put("organizationIdentifier", "2.5.4.97");

        return renderConfig(oids, dn, "ext_brseal", brsealExtensions(sanLines));
    }

    private static String renderConfig(
            Map<String, String> oids,
            Map<String, String> dn,
            String extSectionName,
            String extSection) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Generated by quick-pki-cert-api. Use with:\n");
        sb.append("#   openssl req -new -config <this-file> -key <your-key>.pem -out csr.pem\n\n");
        if (!oids.isEmpty()) {
            sb.append("oid_section = oids\n\n");
            sb.append("[oids]\n");
            for (Map.Entry<String, String> e : oids.entrySet()) {
                sb.append(e.getKey()).append(" = ").append(e.getValue()).append('\n');
            }
            sb.append('\n');
        }
        sb.append("[req]\n");
        sb.append("prompt = no\n");
        sb.append("distinguished_name = dn\n");
        sb.append("req_extensions = ").append(extSectionName).append('\n');
        sb.append("default_md = sha256\n\n");

        sb.append("[dn]\n");
        for (Map.Entry<String, String> e : dn.entrySet()) {
            sb.append(e.getKey()).append(" = ").append(escapeValue(e.getValue())).append('\n');
        }
        sb.append('\n');

        sb.append(extSection);
        return sb.toString();
    }

    private static String brcacExtensions(List<String> sanLines) {
        StringBuilder sb = new StringBuilder();
        sb.append("[ext_brcac]\n");
        sb.append("keyUsage = critical, digitalSignature, keyEncipherment\n");
        sb.append("extendedKeyUsage = clientAuth\n");
        sb.append("subjectAltName = @san\n\n");
        sb.append("[san]\n");
        for (String line : sanLines) {
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    static String forQwac(QwacOpensslConfigRequest request) {
        requireNonBlank(request.commonName(), "commonName");
        requireNonBlank(request.country(), "country");
        if (request.country().length() != 2) {
            throw new CertApiException(400, "invalid_request",
                    "'country' must be a two-letter ISO 3166-1 code");
        }
        requireNonBlank(request.organization(), "organization");
        requireNonBlank(request.organizationIdentifier(), "organizationIdentifier");
        List<String> dnsNames = request.dnsNames() == null ? List.of() : request.dnsNames();
        if (dnsNames.isEmpty()) {
            throw new CertApiException(400, "invalid_request",
                    "QWAC requires at least one entry in 'dnsNames'");
        }

        Map<String, String> dn = euQualifiedDn(request.country(), request.stateOrProvince(),
                request.locality(), request.organization(), request.serialNumber(),
                request.organizationIdentifier(), request.commonName());

        List<String> sanLines = new ArrayList<>();
        int i = 1;
        for (String dnsName : dnsNames) {
            sanLines.add("DNS." + i++ + " = " + dnsName);
        }

        List<QcStatement> statements = new ArrayList<>();
        statements.add(EuQualified.qcCompliance());
        statements.add(EuQualified.qcType(EuQualified.OID_QC_TYPE_WEB));
        appendPsd2(statements, request.psd2Roles(), request.ncaName(), request.ncaId());
        appendQcPds(statements, request.pdsLocations());
        String qcDer = encodeQcStatementsAsHex(statements);

        return renderConfig(euQualifiedOids(), dn, "ext_qwac",
                qwacExtensions(sanLines, qcDer));
    }

    static String forQseal(QsealOpensslConfigRequest request) {
        requireNonBlank(request.commonName(), "commonName");
        requireNonBlank(request.country(), "country");
        if (request.country().length() != 2) {
            throw new CertApiException(400, "invalid_request",
                    "'country' must be a two-letter ISO 3166-1 code");
        }
        requireNonBlank(request.organization(), "organization");
        requireNonBlank(request.organizationIdentifier(), "organizationIdentifier");

        Map<String, String> dn = euQualifiedDn(request.country(), request.stateOrProvince(),
                request.locality(), request.organization(), request.serialNumber(),
                request.organizationIdentifier(), request.commonName());

        List<QcStatement> statements = new ArrayList<>();
        statements.add(EuQualified.qcCompliance());
        statements.add(EuQualified.qcType(EuQualified.OID_QC_TYPE_ESEAL));
        if (request.onQscd()) {
            statements.add(EuQualified.qcSSCD());
        }
        appendPsd2(statements, request.psd2Roles(), request.ncaName(), request.ncaId());
        appendQcPds(statements, request.pdsLocations());
        String qcDer = encodeQcStatementsAsHex(statements);

        return renderConfig(euQualifiedOids(), dn, "ext_qseal", qsealExtensions(qcDer));
    }

    private static Map<String, String> euQualifiedDn(
            String country, String stateOrProvince, String locality,
            String organization, String serialNumber, String organizationIdentifier,
            String commonName) {
        // ETSI EN 319 412-1 §5.1.2 / -3 §4.2 RDN order for the EU qualified
        // legal-person subject; matches Csr.x500Name(... QWAC/QSEAL ...).
        Map<String, String> dn = new LinkedHashMap<>();
        dn.put("countryName", country);
        if (stateOrProvince != null && !stateOrProvince.isBlank()) {
            dn.put("stateOrProvinceName", stateOrProvince);
        }
        if (locality != null && !locality.isBlank()) {
            dn.put("localityName", locality);
        }
        dn.put("organizationName", organization);
        if (serialNumber != null && !serialNumber.isBlank()) {
            dn.put("serialNumber", serialNumber);
        }
        dn.put("organizationIdentifier", organizationIdentifier);
        dn.put("commonName", commonName);
        return dn;
    }

    private static Map<String, String> euQualifiedOids() {
        Map<String, String> oids = new LinkedHashMap<>();
        // organizationIdentifier (2.5.4.97) has no built-in short name in
        // openssl; declare it so the [dn] section can use it by name.
        oids.put("organizationIdentifier", "2.5.4.97");
        return oids;
    }

    private static String qwacExtensions(List<String> sanLines, String qcDerHex) {
        StringBuilder sb = new StringBuilder();
        sb.append("[ext_qwac]\n");
        sb.append("keyUsage = critical, digitalSignature, keyEncipherment\n");
        sb.append("extendedKeyUsage = serverAuth, clientAuth\n");
        sb.append("subjectAltName = @san\n");
        // qCStatements (1.3.6.1.5.5.7.1.3) emitted as a raw DER blob: the
        // ETSI / PSD2 payload shapes are awkward to express in openssl's
        // ASN1 macro language, and the binary stays stable as long as the
        // caller's selections do.
        sb.append("1.3.6.1.5.5.7.1.3 = DER:").append(qcDerHex).append('\n');
        sb.append('\n');
        sb.append("[san]\n");
        for (String line : sanLines) {
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    private static String qsealExtensions(String qcDerHex) {
        StringBuilder sb = new StringBuilder();
        sb.append("[ext_qseal]\n");
        sb.append("keyUsage = critical, digitalSignature, nonRepudiation\n");
        // QSEAL explicitly carries no ExtendedKeyUsage extension.
        sb.append("1.3.6.1.5.5.7.1.3 = DER:").append(qcDerHex).append('\n');
        return sb.toString();
    }

    private static void appendPsd2(List<QcStatement> statements, List<String> roleNames,
                                   String ncaName, String ncaId) {
        if (roleNames == null || roleNames.isEmpty()) {
            return;
        }
        if (ncaName == null || ncaName.isBlank() || ncaId == null || ncaId.isBlank()) {
            throw new CertApiException(400, "invalid_request",
                    "'ncaName' and 'ncaId' are required when 'psd2Roles' is supplied");
        }
        Set<EuQualified.Psd2Role> roles = EnumSet.noneOf(EuQualified.Psd2Role.class);
        for (String name : roleNames) {
            try {
                roles.add(EuQualified.Psd2Role.valueOf(name));
            } catch (IllegalArgumentException e) {
                throw new CertApiException(400, "invalid_request",
                        "unknown PSD2 role '" + name + "'; valid roles are "
                                + EuQualified.Psd2Role.PSP_AS + ", " + EuQualified.Psd2Role.PSP_PI
                                + ", " + EuQualified.Psd2Role.PSP_AI + ", " + EuQualified.Psd2Role.PSP_IC);
            }
        }
        statements.add(EuQualified.psd2QcStatement(roles, ncaName, ncaId));
    }

    private static void appendQcPds(List<QcStatement> statements, List<PdsLocationRequest> pdsLocations) {
        if (pdsLocations == null || pdsLocations.isEmpty()) {
            return;
        }
        List<EuQualified.PdsLocation> locations = new ArrayList<>(pdsLocations.size());
        for (PdsLocationRequest loc : pdsLocations) {
            if (loc.url() == null || loc.url().isBlank()
                    || loc.language() == null || loc.language().isBlank()) {
                throw new CertApiException(400, "invalid_request",
                        "each pdsLocations entry must carry both 'url' and 'language'");
            }
            try {
                locations.add(new EuQualified.PdsLocation(loc.url(), loc.language()));
            } catch (IllegalArgumentException e) {
                throw new CertApiException(400, "invalid_request", e.getMessage());
            }
        }
        statements.add(EuQualified.qcPds(locations));
    }

    private static String encodeQcStatementsAsHex(List<QcStatement> statements) {
        try {
            byte[] der = Csr.encodeQcStatements(statements).getEncoded();
            return HexFormat.of().withUpperCase().formatHex(der);
        } catch (IOException e) {
            throw new CertApiException(500, "server_error",
                    "failed to encode qCStatements: " + e.getMessage());
        }
    }

    static String forOsTransport(OsTransportOpensslConfigRequest request) {
        requireNonBlank(request.commonName(), "commonName");
        requireNonBlank(request.country(), "country");
        if (request.country().length() != 2) {
            throw new CertApiException(400, "invalid_request",
                    "'country' must be a two-letter ISO 3166-1 code");
        }
        requireNonBlank(request.organization(), "organization");
        List<String> dnsNames = request.dnsNames() == null ? List.of() : request.dnsNames();
        if (dnsNames.isEmpty()) {
            throw new CertApiException(400, "invalid_request",
                    "OS_TRANSPORT requires at least one entry in 'dnsNames'");
        }
        List<String> uris = request.uris() == null ? List.of() : request.uris();
        if (uris.isEmpty()) {
            throw new CertApiException(400, "invalid_request",
                    "OS_TRANSPORT requires at least one entry in 'uris'");
        }

        Map<String, String> dn = sesameDn(request.country(), request.organization(),
                request.organizationUnits(), request.commonName());

        List<String> sanLines = new ArrayList<>();
        int dnsIdx = 1;
        for (String dnsName : dnsNames) {
            sanLines.add("DNS." + dnsIdx++ + " = " + dnsName);
        }
        int uriIdx = 1;
        for (String uri : uris) {
            sanLines.add("URI." + uriIdx++ + " = " + uri);
        }

        List<String> policies = new ArrayList<>();
        policies.add(Sesame.OID_OS_TRANSPORT_POLICY);
        if (request.certificatePolicies() != null) {
            for (String oid : request.certificatePolicies()) {
                if (oid != null && !oid.isBlank()) {
                    policies.add(oid);
                }
            }
        }

        return renderConfig(Map.of(), dn, "ext_os_transport",
                osTransportExtensions(sanLines, policies));
    }

    static String forOsSigning(OsSigningOpensslConfigRequest request) {
        requireNonBlank(request.commonName(), "commonName");
        requireNonBlank(request.country(), "country");
        if (request.country().length() != 2) {
            throw new CertApiException(400, "invalid_request",
                    "'country' must be a two-letter ISO 3166-1 code");
        }
        requireNonBlank(request.organization(), "organization");
        requireNonBlank(request.extendedKeyUsageOid(), "extendedKeyUsageOid");
        List<String> uris = request.uris() == null ? List.of() : request.uris();
        if (uris.isEmpty()) {
            throw new CertApiException(400, "invalid_request",
                    "OS_SIGNING requires at least one entry in 'uris'");
        }

        Map<String, String> dn = sesameDn(request.country(), request.organization(),
                request.organizationUnits(), request.commonName());

        List<String> sanLines = new ArrayList<>();
        int uriIdx = 1;
        for (String uri : uris) {
            sanLines.add("URI." + uriIdx++ + " = " + uri);
        }

        List<String> policies = new ArrayList<>();
        policies.add(Sesame.OID_OS_SIGNING_POLICY);
        if (request.certificatePolicies() != null) {
            for (String oid : request.certificatePolicies()) {
                if (oid != null && !oid.isBlank()) {
                    policies.add(oid);
                }
            }
        }

        return renderConfig(Map.of(), dn, "ext_os_signing",
                osSigningExtensions(sanLines, policies, request.extendedKeyUsageOid()));
    }

    private static Map<String, String> sesameDn(String country, String organization,
                                                List<String> organizationUnits, String commonName) {
        // Sesame Open Source RDN order: C, O, OU(s), CN. Matches
        // Csr.x500Name(... OS_TRANSPORT/OS_SIGNING ...).
        Map<String, String> dn = new LinkedHashMap<>();
        dn.put("countryName", country);
        dn.put("organizationName", organization);
        if (organizationUnits != null) {
            int idx = 0;
            for (String ou : organizationUnits) {
                if (ou != null && !ou.isBlank()) {
                    dn.put("0.organizationalUnitName." + idx++, ou);
                }
            }
        }
        dn.put("commonName", commonName);
        return dn;
    }

    private static String osTransportExtensions(List<String> sanLines, List<String> policyOids) {
        StringBuilder sb = new StringBuilder();
        sb.append("[ext_os_transport]\n");
        sb.append("keyUsage = critical, digitalSignature\n");
        sb.append("extendedKeyUsage = clientAuth\n");
        sb.append("subjectAltName = @san\n");
        sb.append("certificatePolicies = ").append(joinPolicyIdentifiers(policyOids)).append('\n');
        sb.append('\n');
        sb.append("[san]\n");
        for (String line : sanLines) {
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    private static String osSigningExtensions(List<String> sanLines, List<String> policyOids,
                                              String ekuOid) {
        StringBuilder sb = new StringBuilder();
        sb.append("[ext_os_signing]\n");
        sb.append("keyUsage = critical, digitalSignature, nonRepudiation\n");
        sb.append("extendedKeyUsage = ").append(ekuOid).append('\n');
        sb.append("subjectAltName = @san\n");
        sb.append("certificatePolicies = ").append(joinPolicyIdentifiers(policyOids)).append('\n');
        sb.append('\n');
        sb.append("[san]\n");
        for (String line : sanLines) {
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    // openssl's certificatePolicies syntax accepts a comma-separated list of
    // policy identifiers; each "@<section>" form supports policy qualifiers
    // but we only need bare OIDs, which openssl accepts directly.
    private static String joinPolicyIdentifiers(List<String> policyOids) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < policyOids.size(); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(policyOids.get(i));
        }
        return sb.toString();
    }

    private static String brsealExtensions(List<String> sanLines) {
        StringBuilder sb = new StringBuilder();
        sb.append("[ext_brseal]\n");
        sb.append("keyUsage = critical, digitalSignature, nonRepudiation\n");
        // BRSEAL explicitly carries no ExtendedKeyUsage extension.
        sb.append("subjectAltName = @san\n\n");
        sb.append("[san]\n");
        for (String line : sanLines) {
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    private static String escapeValue(String value) {
        // openssl req treats '#' as a literal in [dn] when prompt = no, but
        // a leading '#' is interpreted as a comment by the parser. Quote any
        // value containing characters that the openssl config parser handles
        // specially (#, $, leading whitespace).
        if (value.isEmpty()) {
            return "\"\"";
        }
        boolean needsQuote = value.indexOf('#') >= 0
                || value.indexOf('$') >= 0
                || value.indexOf('"') >= 0
                || value.charAt(0) == ' ';
        if (!needsQuote) {
            return value;
        }
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static String defaultIfBlank(String value, String fallback) {
        return (value == null || value.isBlank()) ? fallback : value;
    }

    private static void requireNonBlank(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new CertApiException(400, "invalid_request",
                    "'" + field + "' is required");
        }
    }
}
