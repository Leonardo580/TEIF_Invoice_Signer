package org.api;

import com.sun.net.httpserver.HttpServer;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import org.slf4j.Logger;

public class APIEndpoint {
    private static final Logger logger = LoggerFactory.getLogger(APIEndpoint.class);
    public static void main(String[] args){
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress(10000), 0);
            server.createContext("/sign_invoice", new SignInvoiceHandler());
            server.setExecutor(null);
            server.start();
        }catch (IOException e){
            logger.error("Couldn't create a server :(");
        }

    }
}
