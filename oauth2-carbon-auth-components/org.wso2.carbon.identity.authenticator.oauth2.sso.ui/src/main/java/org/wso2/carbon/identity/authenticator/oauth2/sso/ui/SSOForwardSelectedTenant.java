package org.wso2.carbon.identity.authenticator.oauth2.sso.ui;

import java.io.IOException;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.wso2.carbon.identity.authenticator.oauth2.sso.common.OAUTH2SSOAuthenticatorConstants;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.Util;
import org.wso2.carbon.identity.authenticator.oauth2.sso.tenant.TenantProvision;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.authenticator.OAUTH2SSOUIAuthenticator;
import org.wso2.carbon.ui.CarbonUIUtil;
import java.net.URLEncoder;
import java.util.UUID;

public class SSOForwardSelectedTenant extends HttpServlet {
	
	private boolean isAdmin = false;
    private String backEndServerURL;
    private String username;
    
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
    	username = (String) req.getSession().getAttribute("tenantUsername");
		String tenantDomain = (String) req.getParameter("tenantRadio");
		String selectedRole = (String) req.getParameter("selectedRole");
		String tenantContext = Util.getRoleContext();
		
		if (tenantDomain == null) {
			throw new IOException("The selected tenant is null.");
		}

		if(username != null) {
			boolean isProvider = Util.isProvider(selectedRole, tenantContext);
			req.setAttribute(OAUTH2SSOAuthenticatorConstants.IS_ADMIN, isProvider);
			if(username.equals("admin")) { 
				username = username+"@carbon.super";
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
		    backEndServerURL = req.getParameter("backendURL");
	    	HttpSession session = req.getSession();
	    	ServletContext servletContext = session.getServletContext();
	        if (backEndServerURL == null) {
	            backEndServerURL = CarbonUIUtil.getServerURL(servletContext, session);
	        }
	        TenantProvision tenantProvision = new TenantProvision();
	        tenantProvision.setBackEndURL(backEndServerURL);
	        tenantProvision.setIsAdmin(isProvider);
	        boolean checkTenant = tenantProvision.handleTenant(username,session);
	        try {
	        	if(checkTenant) {
		    		RequestDispatcher reqDispatcher = req.getRequestDispatcher(url);
				    req.getSession().setAttribute("CarbonAuthenticator", new OAUTH2SSOUIAuthenticator());
		    		reqDispatcher.forward(req, resp);
		        }else {
		        	Util.handleMalformedResponses(req, resp, tenantProvision.getTenantError());
		        }
		    }catch(Exception e) {
		    	Util.handleMalformedResponses(req, resp, OAUTH2SSOAuthenticatorConstants.ErrorMessageConstants.RESPONSE_NO_DOMAIN_CREATED_BY_PROVIDER_ERROR);
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
    	System.out.println("inside handleMalformed response");
        resp.sendRedirect(getAdminConsoleURL(req) + "oauth2-sso-acs/authFailure.jsp");
    }
    public static String getAdminConsoleURL(HttpServletRequest request) {
        String url = CarbonUIUtil.getAdminConsoleURL(request);
        if (!url.endsWith("/")) {
            url = url + "/";
        }
        if (url.indexOf("/oauth2_acs") != -1) {
            url = url.replace("/oauth2_acs", "");
        }
        return url;
    }
    
}
