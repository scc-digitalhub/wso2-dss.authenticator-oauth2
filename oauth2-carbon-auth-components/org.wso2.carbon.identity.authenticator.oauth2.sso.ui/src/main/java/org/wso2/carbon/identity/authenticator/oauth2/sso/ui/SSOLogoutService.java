package org.wso2.carbon.identity.authenticator.oauth2.sso.ui;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.authenticator.OAUTH2SSOUIAuthenticator;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.session.SSOSessionManager;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.AACRole;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.AuthorizationToken;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.OAUTH2SSOAuthenticatorConstants;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.Util;
import org.wso2.carbon.identity.authenticator.oauth2.sso.tenant.TenantProvision;
import org.wso2.carbon.ui.CarbonSecuredHttpContext;
import org.wso2.carbon.ui.CarbonUIUtil;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 *
 */
public class SSOLogoutService extends HttpServlet {

    public static final Log log = LogFactory.getLog(SSOLogoutService.class);
    /**
     *
     */
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        doPost(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        try {
        	SSOSessionManager ssoManager = SSOSessionManager.getInstance();
        	String externalLogoutPage	= Util.getExternalLogoutPage();
        	String landingPage	= Util.getLandingPage();
        	String sessionIndex = (String) req.getSession().getAttribute(OAUTH2SSOAuthenticatorConstants.IDP_SESSION_INDEX);
        	log.info("session index comming from aac logout: " );
        	log.info(sessionIndex);
            if(sessionIndex!= null) {
        		ssoManager.handleLogout(sessionIndex);
        	}   
            
            log.info("logout filter. externalLogoutPage: " + externalLogoutPage);
        	req.getSession().setAttribute("CarbonAuthenticator", null);    	
            if(externalLogoutPage != null && !externalLogoutPage.isEmpty()){
                handleExternalLogout(req, resp, landingPage);
            } else {
            	clearCookies(req, resp);
                resp.sendRedirect(getAdminConsoleURL(req) + "admin/logout_action.jsp?logoutcomplete=true");
            }

            
        	
        } catch (Exception e) {
            log.error("Error when processing the OAUTH2 Assertion in the request.", e);
        }
    }
    
    private void handleExternalLogout(HttpServletRequest req, HttpServletResponse resp, String landingPage) throws IOException {

        HttpSession currentSession = req.getSession(false);
        if (currentSession != null) {
            // check if current session has expired
            currentSession.removeAttribute(CarbonSecuredHttpContext.LOGGED_USER);
            currentSession.getServletContext().removeAttribute(CarbonSecuredHttpContext.LOGGED_USER);
            try {
                currentSession.invalidate();
                if(log.isDebugEnabled()) {
                    log.debug("Frontend session invalidated");
                }
            } catch (Exception ignored) {
                // Ignore exception when invalidating and invalidated session
            }
        }
        clearCookies(req, resp);
        if (log.isDebugEnabled()) {
            log.debug("Sending to " + landingPage);
        }
        resp.sendRedirect(landingPage);

    }

    private void clearCookies(HttpServletRequest req, HttpServletResponse resp) {
        Cookie[] cookies = req.getCookies();

        for (Cookie curCookie : cookies) {
            if (curCookie.getName().equals("requestedURI")) {
                Cookie cookie = new Cookie("requestedURI", null);
                cookie.setPath("/");
                cookie.setMaxAge(0);
                resp.addCookie(cookie);
            } else if (curCookie.getName().equals(CarbonConstants.REMEMBER_ME_COOKE_NAME)) {
                Cookie cookie = new Cookie(CarbonConstants.REMEMBER_ME_COOKE_NAME, null);
                cookie.setPath("/");
                cookie.setMaxAge(0);
                resp.addCookie(cookie);
            } else if (curCookie.getName().equals("JSESSIONID_DSS")) {
                Cookie cookie = new Cookie("JSESSIONID_DSS", null);
                cookie.setPath("/");
                cookie.setMaxAge(0);
                resp.addCookie(cookie);
            }
        }
    }
    
    private static String getAdminConsoleURL(HttpServletRequest request) {
        String url = CarbonUIUtil.getAdminConsoleURL(request);
        if (!url.endsWith("/")) {
            url = url + "/";
        }
        if (url.indexOf("/oauth2_acs") != -1) {
            url = url.replace("/oauth2_acs", "");
        }
        return url;
    }
    private void logInformation(String info) {
    	if (log.isDebugEnabled()) {
            log.info(info);
        }
    }
}