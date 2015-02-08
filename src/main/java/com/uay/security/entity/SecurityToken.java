package com.uay.security.entity;


import com.uay.security.util.SecurityTokenUtil;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.util.StringUtils;

public class SecurityToken {
    private String username;
    private long expirationDate;
    private String signature;

    public SecurityToken(String token) {
        String tokenAsPlainText = new String(Base64.decode(token.getBytes()));
        String[] decodedToken = StringUtils.delimitedListToStringArray(tokenAsPlainText, SecurityTokenUtil.DELIMITER);
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

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || !(obj instanceof SecurityToken)) return false;
        SecurityToken securityToken = (SecurityToken) obj;

        return this.getUsername().equals(securityToken.getUsername())
                && this.getSignature().equals(securityToken.getSignature());
    }

    @Override
    public int hashCode() {
        return username.hashCode() + signature.hashCode() * 37;
    }
}
