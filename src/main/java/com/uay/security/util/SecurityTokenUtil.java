package com.uay.security.util;

import org.springframework.security.crypto.codec.Base64;
import org.springframework.util.StringUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SecurityTokenUtil {

    public static final String DELIMITER = ":";

    private SecurityTokenUtil() {
    }

    /**
     * Calculates the digital signature for the user. The value is
     * MD5 ("username:tokenExpiryTime:password:key")
     */
    protected static String makeTokenSignature(String username, String password, long tokenExpiryTime, String key) {
        String data = username + ":" + tokenExpiryTime + ":" + password + ":" + key;
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("No MD5 algorithm available!");
        }

        return new String(Base64.encode(digest.digest(data.getBytes())));
    }

    /**
     * Create user's token
     */
    public static String makeToken(String username, String password, long expirationDate, String key) {
        String rawToken = username + DELIMITER + expirationDate + DELIMITER
                + makeTokenSignature(username, password, expirationDate, key);
        return new String(Base64.encode(rawToken.getBytes()));
    }

    /**
     * Decodes the token.
     * @return  String array of [username,expiration date,signature]
     */
    public static SecurityToken decodeToken(String token) {
        for (int j = 0; j < token.length() % 4; j++) {
            token = token + "=";
        }

        if (!Base64.isBase64(token.getBytes())) {
            throw new IllegalArgumentException( "Token was not Base64 encoded; value was '" + token + "'");
        }

        return new SecurityToken(token);
    }

    /**
     * Checks whether provided signature is valid
     */
    public static boolean isValidSignature(String signature, String username, String password,
                                           long expirationDate, String key) {
        String controlSignature = makeTokenSignature(username, password, expirationDate, key);
        return !isTokenExpired(expirationDate) && controlSignature.equals(signature);
    }

    public static boolean isTokenExpired(long tokenExpiryTime) {
        return tokenExpiryTime < System.currentTimeMillis();
    }

    public static class SecurityToken {
        private String username;
        private long expirationDate;
        private String signature;

        public SecurityToken(String token) {
            String tokenAsPlainText = new String(Base64.decode(token.getBytes()));
            String[] decodedToken = StringUtils.delimitedListToStringArray(tokenAsPlainText, DELIMITER);
            if (decodedToken.length == 3) {
                this.username = decodedToken[0];
                this.expirationDate = Long.parseLong(decodedToken[1]);
                this.signature = decodedToken[2];
            }
        }

        public String getUsername() {
            return username;
        }

        public long getExpirationDate() {
            return expirationDate;
        }

        public String getSignature() {
            return signature;
        }
    }
}
