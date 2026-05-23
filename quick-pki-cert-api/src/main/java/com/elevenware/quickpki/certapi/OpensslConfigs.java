package com.elevenware.quickpki.certapi;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
