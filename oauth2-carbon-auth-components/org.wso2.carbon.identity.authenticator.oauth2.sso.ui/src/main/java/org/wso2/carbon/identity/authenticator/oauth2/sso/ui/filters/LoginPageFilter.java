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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.SSOAssertionConsumerService;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.authenticator.OAUTH2SSOUIAuthenticator;
import org.wso2.carbon.ui.CarbonSecuredHttpContext;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.UUID;

/**
 * This servlet filter is used to intercept the login requests coming to a Carbon server.
 * It checks whether they are coming from a user with an authenticated session, if not redirect him
 * to the corresponding identity provider.
 */
public class LoginPageFilter implements Filter {

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {
  	
        if (!(servletRequest instanceof HttpServletRequest)) {
            return;
        }
        if (servletResponse.isCommitted()) {
            return;
        }
        if ("false".equals(servletRequest.getParameter("loginStatus")) ||
                "failed".equals(servletRequest.getParameter("loginStatus"))) {
            ((HttpServletRequest) servletRequest).getSession().setAttribute(
            		OAUTH2SSOAuthenticatorConstants.NOTIFICATIONS_ERROR_MSG,
                    "Service Temporarily Unavailable.");
            ((HttpServletResponse) servletResponse).sendRedirect("../oauth2-sso-acs/authFailure.jsp");
            return;
        }
        if (Util.getLandingPage() != null) {
        	((HttpServletRequest) servletRequest).getSession().setAttribute("CarbonAuthenticator", null);
            ((HttpServletResponse) servletResponse).sendRedirect(Util.getLandingPage());
        } else {
        	String state =  UUID.randomUUID().toString();
        	((HttpServletRequest) servletRequest).getSession().removeAttribute(OAUTH2SSOAuthenticatorConstants.OAUTH2_AUTH_CODE_STATE);
        	servletRequest.removeAttribute(OAUTH2SSOAuthenticatorConstants.OAUTH2_AUTH_CODE_STATE);
        	// add new state attribute
        	((HttpServletRequest) servletRequest).getSession().setAttribute(OAUTH2SSOAuthenticatorConstants.OAUTH2_AUTH_CODE_STATE, state);
        	String url = Util.getAuthorizationUrl() + "?"
        			+ "response_type=code"
        			+ "&client_id="+Util.getClientId()
        			+ "&redirect_uri="+Util.getRedirectUrl()
        			+ "&scope="+Util.getScopesListUserInfo()
        			+ "&approval_prompt=force" // auto
        			+ "&access_type=offline" // possibility to refresh token
        			+ "&state="+state;
        	((HttpServletResponse)servletResponse).sendRedirect(url);
        }
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
