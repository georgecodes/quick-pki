package com.elevenware.pki.mtls;

import io.undertow.Undertow;
import io.undertow.util.HeaderMap;
import io.undertow.util.HeaderValues;
import io.undertow.util.HttpString;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MtlsTests {

    static Undertow server;
    static int port = startServer();

    @Test
    void test() throws IOException, InterruptedException {



        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(String.format("http://localhost:%d/", port)))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        System.out.println(response.body());
        assertEquals(200, response.statusCode());

    }

    public static int startServer() {

        SSLContext sslContext = SSLContext.getInstance("TLS");
        server = Undertow.builder()
                .addHttpListener(0, "localhost")
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

}
