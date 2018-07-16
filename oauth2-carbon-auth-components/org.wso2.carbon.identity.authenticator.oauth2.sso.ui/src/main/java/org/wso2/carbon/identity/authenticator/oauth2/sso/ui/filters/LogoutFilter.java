package org.wso2.carbon.identity.authenticator.oauth2.sso.ui.filters;

import org.wso2.carbon.identity.authenticator.oauth2.sso.common.OAUTH2SSOAuthenticatorConstants;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.Util;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.SSOAssertionConsumerService;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.authenticator.OAUTH2SSOUIAuthenticator;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.internal.OAUTH2SSOAuthenticatorUIDSComponent;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.session.SSOSessionManager;
import org.wso2.carbon.ui.CarbonSecuredHttpContext;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.UUID;

/**
 * This servlet filter is used to intercept the logout requests coming to a Carbon server.
 *
 */
public class LogoutFilter implements Filter {

	private static final Log log = LogFactory.getLog(LogoutFilter.class);
	
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {

        SSOSessionManager ssoManager = SSOSessionManager.getInstance();
        String sessionIndex = (String)((HttpServletRequest) servletRequest).getSession().getAttribute(OAUTH2SSOAuthenticatorConstants.IDP_SESSION_INDEX);
    	if(sessionIndex!= null) {
    		ssoManager.handleLogout(sessionIndex);
    	}
    	String landingPage = Util.getLandingPage();
    	((HttpServletResponse) servletResponse).sendRedirect(landingPage);
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
