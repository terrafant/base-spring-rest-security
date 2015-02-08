package com.uay.security.overrides;


import com.uay.common.Versions;
import com.uay.security.service.SessionManager;
import com.uay.security.util.HeaderUtil;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.node.ObjectNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final String TOKEN_FIELD_NAME = "token";
    @Autowired
    private HeaderUtil headerUtil;
    @Autowired
    private SessionManager sessionManager;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {
        try {
            String token = headerUtil.createAuthToken(authentication);
            sessionManager.addSession(authentication);
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode node = mapper.createObjectNode();
            node.put(TOKEN_FIELD_NAME, token);
            response.setContentType(Versions.V1_0);
            PrintWriter out = response.getWriter();
            out.print(node.toString());
            out.flush();
            out.close();
        } catch (GeneralSecurityException e) {
            throw new ServletException("Unable to create the auth token", e);
        }
        ((CredentialsContainer)authentication).eraseCredentials();
        clearAuthenticationAttributes(request);
    }

}

