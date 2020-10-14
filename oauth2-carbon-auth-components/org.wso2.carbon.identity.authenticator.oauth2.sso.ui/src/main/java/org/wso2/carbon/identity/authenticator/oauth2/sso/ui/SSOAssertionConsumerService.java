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
public class SSOAssertionConsumerService extends HttpServlet {

    public static final Log log = LogFactory.getLog(SSOAssertionConsumerService.class);
    public static final String SSO_TOKEN_ID = "ssoTokenId";
    private String access_token;
    private String error_reason = OAUTH2SSOAuthenticatorConstants.ErrorMessageConstants.RESPONSE_MALFORMED;
    private boolean isAdmin = false;
    private String backEndServerURL;
    private String username;
    /**
     *
     */
    private static final long serialVersionUID = 5451353570561170887L;
    /**
     * session timeout happens in 10 hours
     */
    private static final int SSO_SESSION_EXPIRE = 36000;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        doPost(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	
        String auth_code = req.getParameter(OAUTH2SSOAuthenticatorConstants.HTTP_ATTR_OAUTH2_RESP_AUTH_CODE);
        String state_code = req.getParameter(OAUTH2SSOAuthenticatorConstants.OAUTH2_AUTH_CODE_STATE);
        String state_code_session = (String) req.getSession().getAttribute(OAUTH2SSOAuthenticatorConstants.OAUTH2_AUTH_CODE_STATE);
        this.isAdmin = false;
        
        this.logInformation("authorization_code: "+auth_code+" state: "+state_code_session);
        if (log.isDebugEnabled()) { 
            Enumeration<?> headerNames = req.getHeaderNames();
            log.debug("[Request Headers] :");
            while (headerNames.hasMoreElements()) {
                String headerName = (String) headerNames.nextElement();
                log.debug(">> " + headerName + ":" + req.getHeader(headerName));
            }

            Enumeration<?> params = req.getParameterNames();
            log.debug("[Request Parameters] :");
            while (params.hasMoreElements()) {
                String paramName = (String) params.nextElement();
                log.debug(">> " + paramName + ":" + req.getParameter(paramName));
            }
        }

        // If OAUTH2 Response is not present in the redirected req, send the user to an error page.
        if (auth_code == null || !state_code.equals(state_code_session)) {
            log.error("authorization_code or state doesn't match.");
            Util.handleMalformedResponses(req, resp, OAUTH2SSOAuthenticatorConstants.ErrorMessageConstants.RESPONSE_NOT_PRESENT);
            return;
        }
        try {
        	clearCookies(req, resp);
            handleOAUTH2Responses(req, resp, auth_code);
        } catch (Exception e) {
            log.error("Error when processing the OAUTH2 Assertion in the request.", e);
            Util.handleMalformedResponses(req, resp, this.error_reason);
        }
    }
    
    /**
     * Handle POST request to retrieve the access_token after obtaining the authorization code
     * @throws IOException 
     */
    private void getAccessToken (HttpServletRequest req, HttpServletResponse resp, String toBeSent, String type) throws Exception {
    	try {
	    	String url_token = Util.getTokenUrl();
	    	MultiValueMap<String,String> dataToBeSent = new LinkedMultiValueMap<String,String>();
	    	dataToBeSent.add("client_id", Util.getClientId());
	    	dataToBeSent.add("client_secret", Util.getClientSecret());
	    	dataToBeSent.add("grant_type", "authorization_code");
	    	if(type.equals("refresh")) {
	    		dataToBeSent.add("grant_type", "refresh_token");
		    	dataToBeSent.add("refresh_token", toBeSent);
	    	}else {
	    		dataToBeSent.add("redirect_uri", Util.getRedirectUrl());
	        	dataToBeSent.add("code", toBeSent);
	    	}
	    	this.logInformation("data to be sent to authtoken: "+dataToBeSent.toString());
	    	HttpHeaders headers = new HttpHeaders();
	    	MediaType contType = MediaType.APPLICATION_FORM_URLENCODED;
	        headers.setContentType(contType);
	        HttpEntity<MultiValueMap<String,String>> requestBody = new HttpEntity<MultiValueMap<String,String>>(dataToBeSent, headers);
	        RestTemplate restTemplate = new RestTemplate();
	        HttpMessageConverter formHttpMessageConverter = new FormHttpMessageConverter();
	        HttpMessageConverter jsonHttpMessageConverternew = new  MappingJackson2HttpMessageConverter();
			List<HttpMessageConverter<?>> list = new ArrayList<HttpMessageConverter<?>>();
			list.add(formHttpMessageConverter);
			list.add(jsonHttpMessageConverternew);
			restTemplate.setMessageConverters(list);
			AuthorizationToken response = restTemplate.postForObject(url_token, requestBody, AuthorizationToken.class);
			this.logInformation("obtain access_token: "+response.getAccess_token());
	        this.access_token = response.getAccess_token();
    	}catch(Exception e) {
    		log.error("Error obtaining token: "+e.getMessage());
    		this.access_token = null;
    		this.error_reason = OAUTH2SSOAuthenticatorConstants.ErrorMessageConstants.RESPONSE_TOKEN_ERROR;
    		throw new Exception("Error obtaining token: " + OAUTH2SSOAuthenticatorConstants.ErrorMessageConstants.RESPONSE_TOKEN_ERROR);
    	}
    }
    
    /**
     * Handle GET request to retrieve the API response using the generated token
     * @throws IOException 
     */
    @SuppressWarnings("unchecked")
	private Map<String,Object> handleAPI_GET_Request(HttpServletRequest req, HttpServletResponse resp,String urlAPI) throws IOException {
    	
    	try {
	    	String urlApi = urlAPI; //Util.getApiUserInfoUrl();
	    	HttpHeaders headers = new HttpHeaders();
	    	headers.add("Authorization","Bearer "+this.access_token);
	    	HttpEntity<String> httpEntity = new HttpEntity<>(headers);
	
	    	RestTemplate restTemplate = new RestTemplate();
	    	ResponseEntity<Map> response = restTemplate.exchange(urlApi, HttpMethod.GET, httpEntity, Map.class);
	    	this.logInformation("response of API call:  "+response.getBody()); 
			return response.getBody();
    	}catch(Exception e){
    		this.error_reason = OAUTH2SSOAuthenticatorConstants.ErrorMessageConstants.RESPONSE_USER_ERROR;
    		return null;
    	}
    	
    }
    
    /**
     * Handle GET request to retrieve the API ROLES response using the generated token
     * @throws IOException 
     */
    @SuppressWarnings("unchecked")
	private List<AACRole> handleAPI_ROLES_Request (HttpServletRequest req, HttpServletResponse resp,String urlAPI) throws IOException {
    	
    	try {
	    	String urlApi = urlAPI;
	    	List<AACRole> rolesList = new ArrayList<AACRole>();
	    	HttpHeaders headers = new HttpHeaders();
	    	headers.add("Authorization","Bearer "+this.access_token);
	    	HttpEntity<String> httpEntity = new HttpEntity<>(headers);
	
	    	RestTemplate restTemplate = new RestTemplate();
			ResponseEntity<ArrayList> response = restTemplate.exchange(urlApi, HttpMethod.GET, httpEntity, ArrayList.class);
			this.logInformation("response of ROLES API request :  "+response.getBody());
			AACRole role = new AACRole();
			String roleName,context,space,definedContext;
			definedContext = Util.getRoleContext();
			List<String> tenantList = new ArrayList<String>();
			for(int i = 0;i<response.getBody().size();i++) {
				Map<String,String> entityRow = (Map<String, String>) response.getBody().get(i);
				roleName = entityRow.get("role");
				context = entityRow.get("context");
				space = entityRow.get("space");
				// in case there are more than one role for the same space we need to get the higher level of permission
				if(context!= null && space!= null && context.equals(definedContext)) {
					this.logInformation("currentRoleName: "+roleName+ " currentContext: "+context+" currentSpace: "+space+" definedContext: "+definedContext);
					if(tenantList.contains(space) && roleName.equals(Util.getRoleProvider())) {
						this.logInformation("Update space: "+space+ " with rolename: "+roleName);
						// update role to provider for the specific space
						for(int j = 0;j<rolesList.size();j++) {
							if(rolesList.get(j).getSpace().equals(space)) {
								rolesList.get(j).setRole(roleName);
							}
						}
					} else if(!tenantList.contains(space)) {
						this.logInformation("insert space: "+space+ " with rolename: "+roleName);
						role = new AACRole();
						role.setContext(context);
						role.setRole(roleName);
						role.setSpace(space);
						rolesList.add(role);
						tenantList.add(space);
					}
				}
			}  
	    	return rolesList;
    	}catch(Exception e) {
    		this.error_reason = OAUTH2SSOAuthenticatorConstants.ErrorMessageConstants.RESPONSE_ROLES_LIST_ERROR;
    		return null;
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
    private void handleOAUTH2Responses(HttpServletRequest req, HttpServletResponse resp, String auth_code)
            throws ServletException, IOException, Exception {
        
        String username = null;
        String tenantDomain = Util.getTenantDefault();
        try {
	        if(auth_code!= null) {
	        	getAccessToken(req,resp,auth_code,"access_token");
	        	if(this.access_token != null) {
		        	Map<String,Object> userInfo = handleAPI_GET_Request(req, resp, Util.getApiUserInfoUrl());
		        	if(userInfo != null) {
		        		username = (String) userInfo.get(Util.getLoginAttributeName());
			        	boolean roleProvision = Util.getApiRoleInfoUrl() != null && !Util.getApiRoleInfoUrl().equals("");
			        	if(roleProvision) {
			        		List<AACRole> rolesInfo = handleAPI_ROLES_Request(req, resp, Util.getApiRoleInfoUrl());
			        		if(rolesInfo != null && rolesInfo.size()>0) {
			        			if (rolesInfo.size() == 1) { // only 1 tenant available
			        				tenantDomain = (String) rolesInfo.get(0).getSpace();
			        				String tenantRole = (String) rolesInfo.get(0).getRole();
			        				String context = (String) rolesInfo.get(0).getContext();
			        				boolean isProvider = Util.isProvider(tenantRole, context);
			    					if(isProvider) {
			    						this.isAdmin = isProvider;
			    					}
			        			} else { // multiple tenants, user needs to choose one
			        				selectTenant(req, resp, rolesInfo, username); // redirects to tenant selection
			        				return; // without returning, it would execute the remaining code before the user can select the tenant
			        			}
			        		} else {
			        			this.error_reason = OAUTH2SSOAuthenticatorConstants.ErrorMessageConstants.RESPONSE_ROLE_MISSING_ERROR;
			        			Util.handleMalformedResponses(req, resp, OAUTH2SSOAuthenticatorConstants.ErrorMessageConstants.RESPONSE_ROLE_MISSING_ERROR);
			        			throw new Exception("No roles in AAC.This service is not enabled for your organization. Please contact the administrator of your organization.");
			        		}
			        	}
			        	username = username+"@"+tenantDomain;
			        	this.logInformation("user name: "+username);
		        	}
	        	}
	        }
	        if (log.isDebugEnabled()) {
	            log.debug("A username is extracted from the response. : " + username);
	        }
	
	        if (username == null) {
	            log.error("OAUTH2Response does not contain the username");
	            this.error_reason = OAUTH2SSOAuthenticatorConstants.ErrorMessageConstants.RESPONSE_USER_ERROR;
	            throw new Exception("OAUTH2Response does not contain the username");
	        }
	
	        if(username != null) {
		        // Set the OAUTH2 access_token as a HTTP Attribute
//		        req.setAttribute(OAUTH2SSOAuthenticatorConstants.HTTP_ATTR_OAUTH2_RESP_TOKEN, this.access_token);
		        req.setAttribute(OAUTH2SSOAuthenticatorConstants.LOGGED_IN_USER, username);
		        req.setAttribute(OAUTH2SSOAuthenticatorConstants.HTTP_POST_PARAM_OAUTH2_ROLES, tenantDomain);
		        req.setAttribute(OAUTH2SSOAuthenticatorConstants.IS_ADMIN, this.isAdmin);
		        req.getSession().setAttribute(OAUTH2SSOAuthenticatorConstants.LOGGED_IN_USER, username);
		        String sessionIndex = null;
		        sessionIndex = UUID.randomUUID().toString();
		        String url = req.getRequestURI();
		        url = url.replace("oauth2_acs","carbon/admin/login_action.jsp?username=" + URLEncoder.encode(username, "UTF-8"));
		        if(sessionIndex != null) {
		            url += "&" + OAUTH2SSOAuthenticatorConstants.IDP_SESSION_INDEX + "=" + URLEncoder.encode(sessionIndex, "UTF-8");
		            req.getSession().setAttribute(OAUTH2SSOAuthenticatorConstants.IDP_SESSION_INDEX, sessionIndex);
		        }
		        if(log.isDebugEnabled()) {
		            log.debug("Forwarding to path : " + url);
		        }
		        try {
			        backEndServerURL = req.getParameter("backendURL");
			    	HttpSession session = req.getSession();
			    	ServletContext servletContext = session.getServletContext();
			        if (backEndServerURL == null) {
			            backEndServerURL = CarbonUIUtil.getServerURL(servletContext, session);
			        }
			        TenantProvision tenantProvision = new TenantProvision();
			        tenantProvision.setBackEndURL(backEndServerURL);
			        tenantProvision.setIsAdmin(this.isAdmin);
			        boolean checkTenant = tenantProvision.handleTenant(username,session);
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
        }catch(Exception e) {
    		log.error("Error handling Oauth2 reponse: "+e.getMessage());
    		this.error_reason = OAUTH2SSOAuthenticatorConstants.ErrorMessageConstants.RESPONSE_TOKEN_ERROR;
            return;
    	}
    }  
    /**
     * Redirect to tenant selection page.
     *
     * @param req				HttpServletRequest
     * @param resp				HttpServletResponse
     * @param tenantsList		Contains the list of tenants
     * @param username			Username
     * @throws ServletException Error while redirecting
     * @throws IOException 		Error while redirecting
     */
    private void selectTenant(HttpServletRequest req, HttpServletResponse resp, List<AACRole> tenantList, String username) throws ServletException, IOException {
    	req.getSession(false).setAttribute("tenantList", tenantList); // list of tenants for current user
    	req.getSession(false).setAttribute("tenantSelectedURL", Util.getTenantSelectedUrl()); // URL to redirect to after tenant is selected
    	req.getSession(false).setAttribute("tenantUsername", username); // will be needed after the redirect
    	String url = Util.getSelectTenantUrl();
    	resp.sendRedirect(url); // redirects to tenant selection page
    	return;
    }
    
    private void handleExternalLogout(HttpServletRequest req, HttpServletResponse resp, String externalLogoutPage) throws IOException {

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
            log.debug("Sending to " + externalLogoutPage);
        }
        resp.sendRedirect(externalLogoutPage);

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
            }
        }
    }
    private void logInformation(String info) {
    	if (log.isDebugEnabled()) {
            log.info(info);
        }
    }
}
