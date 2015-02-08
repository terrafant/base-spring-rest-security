package com.uay.security.util;

import org.junit.Test;
import org.springframework.security.crypto.codec.Base64;

import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;

public class SecurityTokenUtilTest {

    public static final String USERNAME = "test";
    public static final String PASSWORD = "password";
    public static final String KEY = "key";
    public static final long EXPIRATION_DATE = System.currentTimeMillis() + HeaderUtil.TWO_WEEKS_MS;
    public static final int SIGNATURE_LENGTH = 24;

    @Test
    public void testGenerateTokenSinature() throws NoSuchAlgorithmException {
        String signature = SecurityTokenUtil.makeTokenSignature(USERNAME, PASSWORD, EXPIRATION_DATE, KEY);
        assertNotNull(signature);
        assertEquals(SIGNATURE_LENGTH, signature.length());
        assertTrue(Base64.isBase64(signature.getBytes()));
    }

    @Test
    public void testMakeToken() {
        String token = SecurityTokenUtil.makeToken(USERNAME, PASSWORD, EXPIRATION_DATE, KEY);
        assertNotNull(token);
        assertTrue(token.length() > 0);
        assertTrue(Base64.isBase64(token.getBytes()));
    }

    @Test
    public void testDecodeToken() {
        String signature = SecurityTokenUtil.makeTokenSignature(USERNAME, PASSWORD, EXPIRATION_DATE, KEY);
        String token = SecurityTokenUtil.makeToken(USERNAME, PASSWORD, EXPIRATION_DATE, KEY);
        SecurityTokenUtil.SecurityToken securityToken = SecurityTokenUtil.decodeToken(token);

        assertNotNull(securityToken);
        assertEquals(USERNAME, securityToken.getUsername());
        assertEquals(EXPIRATION_DATE, securityToken.getExpirationDate());
        assertEquals(signature, securityToken.getSignature());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecodeTokenWrongLength() {
        SecurityTokenUtil.decodeToken("212qя");
    }

    @Test
    public void testCheckSignatureValidityCorrect() {
        String signature = SecurityTokenUtil.makeTokenSignature(USERNAME, PASSWORD, EXPIRATION_DATE, KEY);
        assertTrue(SecurityTokenUtil.isValidSignature(signature, USERNAME, PASSWORD, EXPIRATION_DATE, KEY));
    }

    @Test
    public void testCheckSignatureValidityWrongDate() {
        long expirationDate = System.currentTimeMillis() - 1;
        String signature = SecurityTokenUtil.makeTokenSignature(USERNAME, PASSWORD, expirationDate, KEY);
        assertFalse(SecurityTokenUtil.isValidSignature(signature, USERNAME, PASSWORD, expirationDate, KEY));
    }
}