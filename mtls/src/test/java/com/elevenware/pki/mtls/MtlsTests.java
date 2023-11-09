package com.elevenware.pki.mtls;

import com.elevenware.quickpki.QuickPki;
import io.undertow.Undertow;
import io.undertow.util.HeaderMap;
import io.undertow.util.HeaderValues;
import io.undertow.util.HttpString;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.awt.desktop.QuitEvent;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MtlsTests {

    static Undertow server;
    static int port;
    static QuickPki serverPki;
    static QuickPki clientPki;

    @Test
    void test() throws Exception {

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(clientPki.);

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(String.format("http://localhost:%d/", port)))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        System.out.println(response.body());
        assertEquals(200, response.statusCode());

    }

    public static int startServer() throws Exception {

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[] { new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }}, null);

        server = Undertow.builder()
                .addHttpsListener(0, "localhost", sslContext)
                .setHandler(exchange -> {
                    HeaderMap requestHeaders = exchange.getRequestHeaders();
                    Map<String,String> theHeaders = new HashMap<>();
                    for(HttpString key: requestHeaders.getHeaderNames()) {
                        HeaderValues strings = requestHeaders.get(key);
                        theHeaders.put(key.toString(), strings.element());
                    }
                    String data = "response";
                    exchange.getResponseSender().send(data);
                }).build();
        server.start();
        Undertow.ListenerInfo listenerInfo = server.getListenerInfo().get(0);
        InetSocketAddress addr = (InetSocketAddress) listenerInfo.getAddress();
        return addr.getPort();
    }

    @BeforeAll
    public static void setup() throws Exception {
        Provider provider = new BouncyCastleProvider();
        clientPki = QuickPki.builder()
                .withIssuer("client issuer")
                .withProvider(provider)
                .build();
        serverPki = QuickPki.builder()
                .withIssuer("server issuer")
                .withProvider(provider)
                .build();
        port = startServer();
    }

}
