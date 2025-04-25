package org.api;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.example.XadesSignerForTEIF;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class SignInvoiceHandler implements HttpHandler {
    private static final Logger logger = LoggerFactory.getLogger(SignInvoiceHandler.class);

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if ("POST".equalsIgnoreCase(exchange.getRequestMethod())){
            InputStream requestedBody = exchange.getRequestBody();
            String xmlContent= new Scanner(requestedBody, StandardCharsets.UTF_8)
                    .useDelimiter("\\A")
                    .next();
            requestedBody.close();
            String signed_string_invoice = "";
            try {
                signed_string_invoice = new XadesSignerForTEIF().signAndGetText(xmlContent);
            }catch (Exception e){
                logger.error("An error occurred while signing !: ", e);
                throw new RuntimeException(e);

            }
            exchange.getResponseHeaders().set("Content-Type", "application/octet-stream");
            exchange.sendResponseHeaders(200, signed_string_invoice.length());
            OutputStream os = exchange.getResponseBody();
            os.write(signed_string_invoice.getBytes());
            os.close();

        }else {
            String error = "Only POST method are allowed >:(";
            exchange.sendResponseHeaders(405, error.length());
            OutputStream os = exchange.getResponseBody();
            os.write(error.getBytes());
            os.close();
        }

    }
}
