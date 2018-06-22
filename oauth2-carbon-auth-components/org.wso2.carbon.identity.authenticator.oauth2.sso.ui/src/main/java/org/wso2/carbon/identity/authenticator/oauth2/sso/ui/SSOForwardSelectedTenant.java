package org.wso2.carbon.identity.authenticator.oauth2.sso.ui;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.wso2.carbon.identity.authenticator.oauth2.sso.common.OAUTH2SSOAuthenticatorConstants;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.Util;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.authenticator.OAUTH2SSOUIAuthenticator;

import java.net.URLEncoder;

public class SSOForwardSelectedTenant extends HttpServlet {

	@Override
	public void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
		String username = (String) req.getSession().getAttribute("tenantUsername");
		String tenantDomain = (String) req.getParameter("tenantRadio");
		String tenantContext = Util.getRoleContext();
		
		if (tenantDomain == null) {
			throw new IOException("The selected tenant is null.");
		}

		if(false) { //!username.contains("@")
			username = username+"@"+tenantContext+"@"+tenantDomain;
		} else {
			username = username+"@"+tenantDomain;
		}

		if (username == null) {
		    throw new IOException("OAUTH2Response does not contain the username");
		}

		if(username != null) {
			// Set the OAUTH2 access_token as a HTTP Attribute
		    req.setAttribute(OAUTH2SSOAuthenticatorConstants.HTTP_ATTR_OAUTH2_RESP_TOKEN, req.getSession().getAttribute("refresh_token"));
		    req.setAttribute(OAUTH2SSOAuthenticatorConstants.LOGGED_IN_USER, username);
		    req.setAttribute(OAUTH2SSOAuthenticatorConstants.HTTP_POST_PARAM_OAUTH2_ROLES, tenantDomain);
		    String sessionIndex = null;
		    sessionIndex = "sessionIndex";
		    String url = req.getRequestURI();
		    url = url.replace("forwardtenant","carbon/admin/login_action.jsp?username=" + URLEncoder.encode(username, "UTF-8"));
		    if(sessionIndex != null) {
		        url += "&" + OAUTH2SSOAuthenticatorConstants.IDP_SESSION_INDEX + "=" + URLEncoder.encode(sessionIndex, "UTF-8");
		        req.getSession().setAttribute(OAUTH2SSOAuthenticatorConstants.IDP_SESSION_INDEX, sessionIndex);
		    }
		    RequestDispatcher reqDispatcher = req.getRequestDispatcher(url);
		    req.getSession().setAttribute("CarbonAuthenticator", new OAUTH2SSOUIAuthenticator());
		    reqDispatcher.forward(req, resp);
		}
	}
}
