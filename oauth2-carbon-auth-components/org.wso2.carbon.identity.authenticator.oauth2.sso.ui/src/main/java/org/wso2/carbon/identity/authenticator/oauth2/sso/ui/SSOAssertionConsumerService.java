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

import org.wso2.carbon.ui.CarbonSecuredHttpContext;
import org.wso2.carbon.ui.CarbonUIUtil;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

/**
 *
 */
public class SSOAssertionConsumerService extends HttpServlet {

    public static final Log log = LogFactory.getLog(SSOAssertionConsumerService.class);
    public static final String SSO_TOKEN_ID = "ssoTokenId";
    private String access_token;
    private String refresh_token;
    private String error_reason = OAUTH2SSOAuthenticatorConstants.ErrorMessageConstants.RESPONSE_MALFORMED;
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
        
        log.info("authorization_code: "+auth_code+" state: "+state_code_session);
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
            handleMalformedResponses(req, resp, OAUTH2SSOAuthenticatorConstants.ErrorMessageConstants.RESPONSE_NOT_PRESENT);
            return;
        }
        try {
            handleOAUTH2Responses(req, resp, auth_code);
        } catch (Exception e) {
            log.error("Error when processing the OAUTH2 Assertion in the request.", e);
            handleMalformedResponses(req, resp, this.error_reason);
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
	    	System.out.println("data to be sent to authtoken: "+dataToBeSent.toString());
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
			log.info("obtain access_token: "+response.getAccess_token());
	        this.access_token = response.getAccess_token();
	        storeSSOTokenCookie(this.access_token,req,resp);
	        this.refresh_token = response.getRefresh_token();
	        //TODO call refresh_token to obtain new token if expired
    	}catch(Exception e) {
    		log.error("Error obtaining token: "+e.getMessage());
    		this.error_reason = OAUTH2SSOAuthenticatorConstants.ErrorMessageConstants.RESPONSE_TOKEN_ERROR;
            return;
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
			System.out.println("response of API call:  "+response.getBody()); 
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
			System.out.println("response of ROLES API request :  "+response.getBody());
			AACRole role = new AACRole();
			String roleName,context,prefix,definedContext;
			String[] temp;
			for(int i = 0;i<response.getBody().size();i++) {
				Map<String,String> entityRow = (Map<String, String>) response.getBody().get(i);
				roleName = entityRow.get("role");
				context = entityRow.get("context");
				prefix = Util.getRolePrefix();
				definedContext = Util.getRoleContext();
				if(roleName.startsWith(prefix) && context.equals(definedContext)) {
					role = new AACRole();
					role.setContext(context);
					temp = roleName.split(prefix);
					role.setRole(temp[1]);
					rolesList.add(role);
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
        String tenantContext = Util.getRoleContext();
        if(auth_code!= null) {
        	getAccessToken(req,resp,auth_code,"access_token");
        	if(this.access_token != null) {
	        	Map<String,Object> userInfo = handleAPI_GET_Request(req, resp, Util.getApiUserInfoUrl());
	        	if(userInfo != null) {
	        		username = (String) userInfo.get(Util.getLoginAttributeName());
		        	boolean tenantProvision = Boolean.parseBoolean(Util.getTenantProvisioningEnabled());
		        	if(tenantProvision) {
		        		List<AACRole> rolesInfo = handleAPI_ROLES_Request(req, resp, Util.getApiRoleInfoUrl());
		        		if(rolesInfo != null && rolesInfo.size()>0) {
		        			tenantDomain = (String) rolesInfo.get(0).getRole();
		        			//TODO handle custom page to select the desired tenant
		        		}else {
		        			this.error_reason = OAUTH2SSOAuthenticatorConstants.ErrorMessageConstants.RESPONSE_ROLE_MISSING_ERROR;
		        			throw new Exception("NO Role.This service is not enabled for your organization. Please contact the administrator of your organization.");
		        		}
		        	}
		        	if(false) { //!username.contains("@")
		        		username = username+"@"+tenantContext+"@"+tenantDomain;
		        	}else {
		        		username = username+"@"+tenantDomain;
		        	}
		        	log.info("user name: "+username);
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
	        req.setAttribute(OAUTH2SSOAuthenticatorConstants.HTTP_ATTR_OAUTH2_RESP_TOKEN, this.access_token);
	        req.setAttribute(OAUTH2SSOAuthenticatorConstants.LOGGED_IN_USER, username);
	        req.setAttribute(OAUTH2SSOAuthenticatorConstants.HTTP_POST_PARAM_OAUTH2_ROLES, tenantDomain);
	        req.getSession().setAttribute("refresh_token", this.refresh_token);
	        String sessionIndex = null;
	        sessionIndex = "sessionIndex";
	        String url = req.getRequestURI();
	        url = url.replace("oauth2_acs","carbon/admin/login_action.jsp?username=" + URLEncoder.encode(username, "UTF-8"));
	        if(sessionIndex != null) {
	            url += "&" + OAUTH2SSOAuthenticatorConstants.IDP_SESSION_INDEX + "=" + URLEncoder.encode(sessionIndex, "UTF-8");
	            req.getSession().setAttribute(OAUTH2SSOAuthenticatorConstants.IDP_SESSION_INDEX, sessionIndex);
	        }
	        if(log.isDebugEnabled()) {
	            log.debug("Forwarding to path : " + url);
	        }
	        RequestDispatcher reqDispatcher = req.getRequestDispatcher(url);
	        req.getSession().setAttribute("CarbonAuthenticator", new OAUTH2SSOUIAuthenticator());
	        reqDispatcher.forward(req, resp);
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
    private void handleMalformedResponses(HttpServletRequest req, HttpServletResponse resp,
                                          String errorMsg) throws IOException {
        HttpSession session = req.getSession();
        session.setAttribute(OAUTH2SSOAuthenticatorConstants.NOTIFICATIONS_ERROR_MSG, errorMsg);
        resp.sendRedirect(getAdminConsoleURL(req) + "oauth2-sso-acs/notifications.jsp?error="+errorMsg);
        return;
    }

    /**
     * Get the admin console url from the request.
     *
     * @param request httpServletReq that hits the ACS Servlet
     * @return Admin Console URL       https://10.100.1.221:8443/acs/carbon/
     */
    private String getAdminConsoleURL(HttpServletRequest request) {
        String url = CarbonUIUtil.getAdminConsoleURL(request);
        if (!url.endsWith("/")) {
            url = url + "/";
        }
        if (url.indexOf("/oauth2_acs") != -1) {
            url = url.replace("/oauth2_acs", "");
        }
        return url;
    }
    
    private void storeSSOTokenCookie(String ssoTokenID, HttpServletRequest req,
                                     HttpServletResponse resp) {
        Cookie ssoTokenCookie = getSSOTokenCookie(req);
        if (ssoTokenCookie == null) {
            ssoTokenCookie = new Cookie(SSO_TOKEN_ID, ssoTokenID);
            ssoTokenCookie.setSecure(true);
            //ssoTokenCookie.setHttpOnly(true);
        }
        ssoTokenCookie.setMaxAge(SSO_SESSION_EXPIRE);
        resp.addCookie(ssoTokenCookie);
    }

    private Cookie getSSOTokenCookie(HttpServletRequest req) {
        Cookie[] cookies = req.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("ssoTokenId".equals(cookie.getName())) {
                    return cookie;
                }
            }
        }
        return null;
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
}