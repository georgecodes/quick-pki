package com.elevenware.quickpki;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;

public class SimpleServer implements Runnable {

    private final int port;
    private final SSLServerSocket serverSocket;
    private boolean keepRunning;

    public SimpleServer(SSLContext sslContext) throws IOException {
        SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();
        serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(0);
        port = serverSocket.getLocalPort();
    }

    @Override
    public void run() {
        keepRunning = true;
        while (keepRunning) {
            try {
                startTlsInt();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    public int start() {
        new Thread(this).start();
        return port;
    }

    public void stop() {
        keepRunning = false;
    }

    void startTlsInt() throws Exception {
        while (keepRunning) {
            try (SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                 BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                 PrintWriter out = new PrintWriter(clientSocket.getOutputStream())) {
                 System.out.println("Client connected");
                 String message;
                 while ((message = in.readLine()) != null) {
                    System.out.println("Received from client: " + message);
                    out.println("Server received: " + message);
                 }
                 System.out.println("done reading from client");

                 String response = "Hello, client!";

                 out.write(response);
                 out.flush();
            } catch (IOException e) {
                System.err.println("Client connection error: " + e.getMessage());
            }

        }
        serverSocket.close();
    }

}
