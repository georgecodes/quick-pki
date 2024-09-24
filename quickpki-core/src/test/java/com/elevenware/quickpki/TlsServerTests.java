package com.elevenware.quickpki;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

public class TlsServerTests {

    private SimpleServer simpleServer;

    @Test
    void server() throws NoSuchAlgorithmException, IOException, KeyManagementException {

        QuickPki pki = QuickPki.createDefault();
        CertificateBundle serverCert = pki.issueCertificate(CertInfo.builder()
                        .subjectName(SubjectName.builder()
                                .commonName("localhost")
                                .build())
                .build());
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(serverCert.keyManagers(), null, new SecureRandom());

        simpleServer = new SimpleServer(sslContext);

        int port = simpleServer.start();

        System.out.println(port);

        String host = "project.127.0.0.1.nip.io";
        host = "localhost";
        SSLContext clientContext = SSLContext.getInstance("TLS");
//        clientContext.init(null, null, new SecureRandom());
        clientContext.init(null, serverCert.getIssuer().trustStore(), new SecureRandom());
        SSLSocketFactory sslSocketFactory = clientContext.getSocketFactory();
    try (SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(host, port)) {    ;
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            out.println("Hello, Server!");
            out.flush();
            out.close();


            // Read the response from the server
        String message = in.readLine();
        while ((message = in.readLine()) != null) {
            System.out.println("Received from server: " + message);
        }
        System.out.println("done reading from server");
        }
     catch (Exception e) {
        e.printStackTrace();
        }
    }

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @AfterEach
    void tearDown() {
        if(simpleServer != null) {
            simpleServer.stop();
        }
    }

}
