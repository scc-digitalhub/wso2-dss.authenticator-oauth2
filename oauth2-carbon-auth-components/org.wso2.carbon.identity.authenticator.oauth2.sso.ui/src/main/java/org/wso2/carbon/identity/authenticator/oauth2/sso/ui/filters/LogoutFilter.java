package org.wso2.carbon.identity.authenticator.oauth2.sso.ui.filters;

import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.OAUTH2SSOAuthenticatorConstants;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.Util;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.session.SSOSessionManager;
import org.wso2.carbon.ui.CarbonSecuredHttpContext;
import org.wso2.carbon.ui.CarbonUILoginUtil;
import org.wso2.carbon.ui.CarbonUIUtil;

import java.io.IOException;

/**
 * This servlet filter is used to intercept the logout requests coming to a Carbon server.
 *
 */
public class LogoutFilter implements Filter {

	private static final Log log = LogFactory.getLog(LogoutFilter.class);
	
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {

        SSOSessionManager ssoManager = SSOSessionManager.getInstance();
        HttpServletRequest req   = (HttpServletRequest) servletRequest;
        HttpServletResponse resp = (HttpServletResponse) servletResponse;        
    	String externalLogoutPage	= Util.getExternalLogoutPage();
    	String logoutService	= Util.getLogoutService();
        String sessionIndex = (String) req.getSession().getAttribute(OAUTH2SSOAuthenticatorConstants.IDP_SESSION_INDEX);
        if(sessionIndex!= null) {
    		ssoManager.handleLogout(sessionIndex);
    	}   
        log.info("logout filter. externalLogoutPage: " + externalLogoutPage);
    	req.getSession().setAttribute("CarbonAuthenticator", null);    	
        if(externalLogoutPage != null && !externalLogoutPage.isEmpty()){
            handleExternalLogout(req, resp, externalLogoutPage, logoutService);
        } else {
        	log.info("Sending to " + getAdminConsoleURL(req) + "admin/logout_action.jsp?logoutcomplete=true");
        	clearCookies(req, resp);
            resp.sendRedirect(getAdminConsoleURL(req) + "admin/logout_action.jsp?logoutcomplete=true");
        }
    }

    private void handleExternalLogout(HttpServletRequest req, HttpServletResponse resp, String externalLogoutPage, String logoutService) throws IOException {
        HttpSession currentSession = req.getSession(false);
        log.info("currentSesssion ");
        log.info(currentSession);
        if (currentSession != null) {
            // check if current session has expired
            currentSession.removeAttribute(CarbonSecuredHttpContext.LOGGED_USER);
            currentSession.getServletContext().removeAttribute(CarbonSecuredHttpContext.LOGGED_USER);
            log.info("reqURI in session: " + currentSession.getAttribute("requestedURI"));
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
            log.debug("Sending to " + externalLogoutPage);
        }
        if(!logoutService.equals(""))
        	externalLogoutPage += "?post_logout_redirect_uri=" + logoutService;
        resp.sendRedirect(externalLogoutPage);
    }

    private void clearCookies(HttpServletRequest req, HttpServletResponse resp) {
        Cookie[] cookies = req.getCookies();
        log.info("inside clearCookies");
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
    
    private void refreshToken() {
		// TODO Auto-generated method stub
	}

	public void destroy() {
        // This method is not required at the moment
    }
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // This method is not required at the moment
    }
}
