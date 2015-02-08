package com.uay.security.util;


import com.uay.security.entity.SecurityToken;
import com.uay.security.service.UserDetailsManager;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.GeneralSecurityException;

@Component
public class HeaderUtil {

    private static final Logger logger = LoggerFactory.getLogger(HeaderUtil.class);

    private static final String HEADER_NAME = "X-Auth-Token";
    public static final long TWO_WEEKS_MS = 1209600000;

    @Value("${token.ttl}")
    private long ttl;

    @Value("${token.seed}")
    private String seed;

    @Autowired
    private UserDetailsManager userDetailsManager;

    public String getTokenHeader(HttpServletRequest request) {
        return request.getHeader(HEADER_NAME);
    }

    public SecurityToken getSecurityToken(HttpServletRequest request) {
        String header = getTokenHeader(request);
        return StringUtils.isNotBlank(header) ? SecurityTokenUtil.decodeToken(header) : null;
    }

    public void addHeader(HttpServletResponse response, Authentication authentication) {
        try {
            String authToken = createAuthToken(authentication);
            response.setHeader(HEADER_NAME, authToken);
        } catch (GeneralSecurityException e) {
            logger.error("Unable to encrypt header", e);
        }
    }

    public String createAuthToken(Authentication authentication) throws GeneralSecurityException {
        String username = userDetailsManager.retrieveUsername(authentication);
        String password = userDetailsManager.retrievePassword(authentication);
        if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password)) {
            throw new GeneralSecurityException("Cannot get user credentials");
        }
        return SecurityTokenUtil.makeToken(username, password, System.currentTimeMillis() + ttl, seed);
    }
}
