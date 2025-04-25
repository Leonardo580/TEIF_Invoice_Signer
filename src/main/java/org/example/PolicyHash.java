package org.example;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Base64;


public class PolicyHash {
    public static String CalculateSHA256Base64(String filepath) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream file_input = new FileInputStream(filepath)){
            byte[] buffer = new byte[8192];
            int bytesread = 0;
            while ((bytesread = file_input.read(buffer)) != -1){
                md.update(buffer, 0, bytesread);
            }
        }
        byte[] hashBytes = md.digest();
        return Base64.getEncoder().encodeToString(hashBytes);

    }
}
