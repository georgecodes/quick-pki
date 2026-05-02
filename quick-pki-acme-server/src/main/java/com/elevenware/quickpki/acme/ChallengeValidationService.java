package com.elevenware.quickpki.acme;

import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Hashtable;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class ChallengeValidationService {

    private static final Logger LOG = LoggerFactory.getLogger(ChallengeValidationService.class);

    private final AcmeConfig config;
    private final HttpClient httpClient;

    ChallengeValidationService(AcmeConfig config) {
        this.config = config;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(config.challengeTimeout())
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    void validate(Authorization authorization, Challenge challenge, String accountThumbprint) {
        String keyAuthorization = challenge.token() + "." + accountThumbprint;
        boolean valid = switch (challenge.type()) {
            case "http-01" -> validateHttp01(authorization.identifierValue(), challenge.token(), keyAuthorization);
            case "dns-01" -> validateDns01(authorization.identifierValue(), keyAuthorization);
            default -> throw new AcmeException(400, "malformed", "Unsupported challenge type");
        };
        if (!valid) {
            LOG.warn("Challenge validation failed challengeId={} type={} identifier={}",
                    challenge.id(), challenge.type(), authorization.identifierValue());
            throw new AcmeException(400, "unauthorized", "Challenge validation failed");
        }
        LOG.info("Challenge validation succeeded challengeId={} type={} identifier={}",
                challenge.id(), challenge.type(), authorization.identifierValue());
    }

    private boolean validateHttp01(String identifier, String token, String keyAuthorization) {
        if (identifier.startsWith("*.")) {
            return false;
        }
        String host = identifier;
        if (host.contains(":") && !host.startsWith("[")) {
            host = "[" + host + "]";
        }
        URI uri = URI.create("http://" + host + "/.well-known/acme-challenge/" + token);
        int attempts = config.challengeAttempts();
        for (int attempt = 0; attempt < attempts; attempt++) {
            try {
                HttpRequest request = HttpRequest.newBuilder(uri)
                        .timeout(config.challengeTimeout())
                        .GET()
                        .build();
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                LOG.debug("HTTP-01 validation attempt={} uri={} status={}", attempt + 1, uri, response.statusCode());
                if (response.statusCode() >= 200 && response.statusCode() < 300
                        && keyAuthorization.equals(response.body().trim())) {
                    return true;
                }
            } catch (Exception ignored) {
                LOG.debug("HTTP-01 validation attempt failed attempt={} uri={}", attempt + 1, uri, ignored);
            }
            // Back off on every failed attempt (non-2xx, body mismatch, or
            // network exception) so retries don't hot-loop the target host
            // when the challenge isn't yet available. Skip the pause after
            // the final attempt - we're about to give up anyway.
            if (attempt < attempts - 1) {
                pauseBeforeRetry();
            }
        }
        return false;
    }

    private boolean validateDns01(String identifier, String keyAuthorization) {
        String name = "_acme-challenge." + (identifier.startsWith("*.") ? identifier.substring(2) : identifier);
        String expected = dnsDigest(keyAuthorization);
        int attempts = config.challengeAttempts();
        for (int attempt = 0; attempt < attempts; attempt++) {
            try {
                if (txtRecords(name).contains(expected)) {
                    LOG.debug("DNS-01 TXT validation matched name={}", name);
                    return true;
                }
                String cname = firstCname(name);
                if (cname != null && txtRecords(cname).contains(expected)) {
                    LOG.debug("DNS-01 CNAME validation matched name={} cname={}", name, cname);
                    return true;
                }
            } catch (Exception ignored) {
                LOG.debug("DNS-01 validation attempt failed attempt={} name={}", attempt + 1, name, ignored);
            }
            // Back off on every failed attempt (no matching TXT yet, or DNS
            // lookup failure) so retries don't hammer the resolver.
            if (attempt < attempts - 1) {
                pauseBeforeRetry();
            }
        }
        return false;
    }

    private String dnsDigest(String keyAuthorization) {
        try {
            return Base64Url.encode(MessageDigest.getInstance("SHA-256")
                    .digest(keyAuthorization.getBytes()));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private List<String> txtRecords(String name) throws Exception {
        Attribute attr = lookup(name, "TXT").get("TXT");
        if (attr == null) {
            return List.of();
        }
        return java.util.Collections.list(attr.getAll()).stream()
                .map(String::valueOf)
                .map(this::unquoteTxt)
                .toList();
    }

    private String firstCname(String name) throws Exception {
        Attribute attr = lookup(name, "CNAME").get("CNAME");
        if (attr == null || attr.size() == 0) {
            return null;
        }
        String cname = String.valueOf(attr.get(0));
        return cname.endsWith(".") ? cname.substring(0, cname.length() - 1) : cname;
    }

    private Attributes lookup(String name, String type) throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
        if (!config.dnsServers().isEmpty()) {
            env.put("java.naming.provider.url", dnsProviderUrl(config.dnsServers()));
        }
        return new InitialDirContext(env).getAttributes(name, new String[]{type});
    }

    private String dnsProviderUrl(List<String> servers) {
        return servers.stream()
                .map(server -> "dns://" + server + "/")
                .reduce((a, b) -> a + " " + b)
                .orElse("");
    }

    private String unquoteTxt(String value) {
        String trimmed = value.trim();
        if (trimmed.startsWith("\"") && trimmed.endsWith("\"") && trimmed.length() >= 2) {
            return trimmed.substring(1, trimmed.length() - 1);
        }
        return trimmed;
    }

    private void pauseBeforeRetry() {
        try {
            Thread.sleep(Math.min(Duration.ofSeconds(1).toMillis(), config.challengeTimeout().toMillis()));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
