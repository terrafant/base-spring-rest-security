package com.uay.security.overrides;

import com.uay.common.Versions;
import com.uay.security.service.SessionManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AbstractAuthenticationTargetUrlRequestHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Component
public class CustomUrlLogoutSuccessHandler extends AbstractAuthenticationTargetUrlRequestHandler
            implements LogoutSuccessHandler {

    @Autowired
    private SessionManager sessionManager;

    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        String resultMessage;
        if (authentication != null) {
            sessionManager.removeSession(authentication);
            resultMessage = "{\"message\":\"Successfully logged out.\"}";
        } else {
            resultMessage = "{\"message\":\"Wrong authentication. Have you used the right username?\"}";
        }
        response.setContentType(Versions.V1_0);
        response.setStatus(HttpServletResponse.SC_OK);
        PrintWriter out = response.getWriter();
        out.print(resultMessage);
        out.flush();
        out.close();
    }
}
