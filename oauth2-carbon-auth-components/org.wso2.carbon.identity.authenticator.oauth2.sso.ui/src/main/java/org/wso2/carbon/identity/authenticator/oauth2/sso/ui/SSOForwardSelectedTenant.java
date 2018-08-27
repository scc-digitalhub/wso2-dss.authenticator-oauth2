package org.wso2.carbon.identity.authenticator.oauth2.sso.ui;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.wso2.carbon.identity.authenticator.oauth2.sso.common.AACRole;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.OAUTH2SSOAuthenticatorConstants;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.Util;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.authenticator.OAUTH2SSOUIAuthenticator;

import java.net.URLEncoder;
import java.util.List;
import java.util.UUID;

public class SSOForwardSelectedTenant extends HttpServlet {
	
	@Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        doPost(req, resp);
    }
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException, IllegalStateException {
		// executes the same logic as the handleOAUTH2Responses method
		// in SSOAssertionConsumerService.java, after tenant is obtained
	    try {
            handleOAUTH2Responses(req, resp);
        }catch(Exception e) {
	    	handleMalformedResponses(req, resp);
	    }
	}
	
	/**
     * Handle OAUTH2 Responses and authenticate.
     *
     * @param req        HttpServletRequest
     * @param resp       HttpServletResponse
     * @param OAUTH2Object OAUTH2 Response object
     * @throws ServletException  Error when redirecting
     * @throws IOException       Error when redirecting
     */
    private void handleOAUTH2Responses(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException, IllegalStateException, Exception {
    	String username = (String) req.getSession().getAttribute("tenantUsername");
		String tenantDomain = (String) req.getParameter("tenantRadio");
		String selectedRole = (String) req.getParameter("selectedRole");
		String tenantContext = Util.getRoleContext();
		
		if (tenantDomain == null) {
			throw new IOException("The selected tenant is null.");
		}

		if(username != null) {
			boolean isProvider = Util.isProvider(selectedRole, tenantContext);
			req.setAttribute(OAUTH2SSOAuthenticatorConstants.IS_ADMIN, isProvider);
			if(!username.contains("@")) { 
	    		username = username+"@"+tenantContext+".super@"+tenantDomain;
	    	}else {
	    		username = username+"@"+tenantDomain;
	    	}
			req.setAttribute(OAUTH2SSOAuthenticatorConstants.HTTP_ATTR_OAUTH2_RESP_TOKEN, req.getSession().getAttribute("refresh_token"));
		    req.setAttribute(OAUTH2SSOAuthenticatorConstants.LOGGED_IN_USER, username);
		    req.setAttribute(OAUTH2SSOAuthenticatorConstants.HTTP_POST_PARAM_OAUTH2_ROLES, tenantDomain);
		    req.getSession().setAttribute(OAUTH2SSOAuthenticatorConstants.LOGGED_IN_USER, username);
		    String sessionIndex = null;
		    sessionIndex = UUID.randomUUID().toString();
		    String url = req.getRequestURI();
		    url = url.replace("forwardtenant","carbon/admin/login_action.jsp?username=" + URLEncoder.encode(username, "UTF-8"));
		    if(sessionIndex != null) {
		        url += "&" + OAUTH2SSOAuthenticatorConstants.IDP_SESSION_INDEX + "=" + URLEncoder.encode(sessionIndex, "UTF-8");
		        req.getSession().setAttribute(OAUTH2SSOAuthenticatorConstants.IDP_SESSION_INDEX, sessionIndex);
		    }
		    RequestDispatcher reqDispatcher = req.getRequestDispatcher(url);
		    OAUTH2SSOUIAuthenticator temp = new OAUTH2SSOUIAuthenticator();
		    System.out.println(temp);
    		if(new OAUTH2SSOUIAuthenticator() != null) {
    			req.getSession().setAttribute("CarbonAuthenticator", temp);
    		    reqDispatcher.forward(req, resp);
    		}
    		else {
    			handleMalformedResponses(req, resp);
    		}
		    
		}
    }
	/**
     * Handle malformed Responses.
     *
     * @param req      HttpServletRequest
     * @param resp     HttpServletResponse
     * @param errorMsg Error message to be displayed in HttpServletResponse.jsp
     * @throws IOException Error when redirecting
     */
    private void handleMalformedResponses(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.sendRedirect("../oauth2-sso-acs/authFailure.jsp");
        return;
    }
}
