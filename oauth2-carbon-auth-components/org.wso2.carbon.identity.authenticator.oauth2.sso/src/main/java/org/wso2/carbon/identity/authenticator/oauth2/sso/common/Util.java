
package org.wso2.carbon.identity.authenticator.oauth2.sso.common;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xerces.impl.Constants;
import org.apache.xerces.util.SecurityManager;
import org.apache.xml.security.c14n.Canonicalizer;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.wso2.carbon.core.security.AuthenticatorsConfiguration;
import org.wso2.carbon.ui.CarbonUIUtil;
import org.xml.sax.SAXException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

//import com.fasterxml.jackson.core.JsonParseException;
//import com.fasterxml.jackson.core.type.TypeReference;
//import com.fasterxml.jackson.databind.JsonMappingException;
//import com.fasterxml.jackson.databind.ObjectMapper;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This class contains all the utility methods required by AAC SSO Authenticator module.
 */
public class Util {
    private  Util(){

    }

    private static final char[] charMapping = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            'k', 'l', 'm', 'n', 'o', 'p'};
    private static final String SECURITY_MANAGER_PROPERTY = Constants.XERCES_PROPERTY_PREFIX +
            Constants.SECURITY_MANAGER_PROPERTY;
    private static final int ENTITY_EXPANSION_LIMIT = 0;
    private static boolean bootStrapped = false;
    private static Log log = LogFactory.getLog(Util.class);
    private static Random random = new Random();
    private static String serviceProviderId = null;
    private static String identityProviderSSOServiceURL = null;
    private static Map<String, String> parameters = new HashMap<String, String>();
    private static String identityProviderSLOServiceURL = parameters.get(
            OAUTH2SSOAuthenticatorConstants.IDENTITY_PROVIDER_SLO_SERVICE_URL);
    private static String loginPage = "/carbon/admin/login.jsp";
    private static String landingPage = null;
    private static String user_info = null;
    private static String externalLogoutPage = null;
    private static boolean logoutSupportedIDP = false;
    private static String assertionConsumerServiceUrl = null;
    private static boolean initSuccess = false;
    private static Properties AACIdpProperties = new Properties();
    private static Map<String, String> cachedIdps = new ConcurrentHashMap<String, String>();
    private static String clientId = null;
	private static String clientSecret = null;
	private static String redirectUrl = null;
	private static String logoutUrl = null;
	private static String authorizationUrl = null;
	private static String tokenUrl = null;
	private static String checkTokenEndpoiuntUrl = null;
	private static String apiUserInfoUrl = null;
	private static String apiRoleInfoUrl = null;
	private static String scopesListUserInfo = null;
	private static String access_token = null;
	private static String refresh_token = null;
	private static String selectTenantUrl = null;
	private static String tenantSelectedUrl = null;

    /**
     * Sets the issuerID and IDP SSO Service URL during the server start-up by reading
     * authenticators.xml
     */
    public static boolean initSSOConfigParams() {

        AuthenticatorsConfiguration authenticatorsConfiguration = AuthenticatorsConfiguration
                .getInstance();
        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig = authenticatorsConfiguration
                .getAuthenticatorConfig(OAUTH2SSOAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (authenticatorConfig != null) {
            parameters = authenticatorConfig.getParameters();
            serviceProviderId = parameters.get(OAUTH2SSOAuthenticatorConstants.SERVICE_PROVIDER_ID);
            identityProviderSSOServiceURL = parameters
                    .get(OAUTH2SSOAuthenticatorConstants.IDENTITY_PROVIDER_SSO_SERVICE_URL);
            identityProviderSLOServiceURL = parameters
                    .get(OAUTH2SSOAuthenticatorConstants.IDENTITY_PROVIDER_SLO_SERVICE_URL);
            loginPage = parameters.get(OAUTH2SSOAuthenticatorConstants.LOGIN_PAGE);
            landingPage = parameters.get(OAUTH2SSOAuthenticatorConstants.LANDING_PAGE);
            externalLogoutPage = parameters.get(OAUTH2SSOAuthenticatorConstants.EXTERNAL_LOGOUT_PAGE);
            logoutSupportedIDP = Boolean.parseBoolean(parameters.get(OAUTH2SSOAuthenticatorConstants.LOGOUT_SUPPORTED_IDP));
            assertionConsumerServiceUrl = parameters.get(OAUTH2SSOAuthenticatorConstants.ASSERTION_CONSUMER_SERVICE_URL);
                       
			clientId = parameters.get(OAUTH2SSOAuthenticatorConstants.CLIENT_ID);
			clientSecret = parameters.get(OAUTH2SSOAuthenticatorConstants.CLIENT_SECRET);
			redirectUrl = parameters.get(OAUTH2SSOAuthenticatorConstants.REDIRECT_URL);
			logoutUrl = parameters.get(OAUTH2SSOAuthenticatorConstants.LOGOUT_URL);
			authorizationUrl = parameters.get(OAUTH2SSOAuthenticatorConstants.AUTHORIZATION_URL);
			tokenUrl = parameters.get(OAUTH2SSOAuthenticatorConstants.TOKEN_URL);
			checkTokenEndpoiuntUrl = parameters.get(OAUTH2SSOAuthenticatorConstants.CHECK_TOKEN_ENDPOINT_URL);
			apiUserInfoUrl = parameters.get(OAUTH2SSOAuthenticatorConstants.API_USER_INFO_URL);
			apiRoleInfoUrl = parameters.get(OAUTH2SSOAuthenticatorConstants.API_ROLE_INFO_URL);
			scopesListUserInfo = parameters.get(OAUTH2SSOAuthenticatorConstants.SCOPES_LIST_USER_INFO);
			selectTenantUrl = parameters.get(OAUTH2SSOAuthenticatorConstants.SELECT_TENANT_URL);
			tenantSelectedUrl = parameters.get(OAUTH2SSOAuthenticatorConstants.TENANT_SELECTED_URL);
        		
            initSuccess = true;
        }
        return initSuccess;
    }

    /**
     * checks whether authenticator enable or disable
     *
     * @return True/False
     */
    public static boolean isAuthenticatorEnabled() {

    	AuthenticatorsConfiguration authenticatorsConfiguration = AuthenticatorsConfiguration
                .getInstance();
        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig = authenticatorsConfiguration
                .getAuthenticatorConfig(OAUTH2SSOAuthenticatorConstants.AUTHENTICATOR_NAME);
        // if the authenticator is disabled, then do not register the servlet filter.
        boolean isEnabled = false;
        if(authenticatorConfig != null && !authenticatorConfig.isDisabled()) {
        	isEnabled = true;
        }
        return isEnabled;
    }

    /**
     * returns the service provider ID of a particular server
     *
     * @return service provider ID
     */
    public static String getServiceProviderId() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return serviceProviderId;
    }

    /**
     * returns the Identity Provider SSO Service URL
     *
     * @return dentity Provider SSO Service URL
     */
    public static String getIdentityProviderSSOServiceURL() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return identityProviderSSOServiceURL;
    }

    /**
     * returns the Identity Provider SSO Service URL
     *
     * @return dentity Provider SSO Service URL
     */
    public static String getIdentityProviderSLOServiceURL() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return identityProviderSLOServiceURL;
    }

    /**
     * returns the Assertion Consumer Service URL
     *
     * @return Assertion Consumer Service URL
     */
    public static String getAssertionConsumerServiceURL() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return assertionConsumerServiceUrl;
    }

    public static String getUser_info() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return user_info;
    }

    /**
     * @param federatedDomain
     * @return
     */
    public static String getIdentityProviderSSOServiceURL(String federatedDomain) {

        if (!initSuccess) {
            initSSOConfigParams();
        }

        String fedeartedIdp = null;

        if (federatedDomain == null) {
            return null;
        }

        String selfDomain = parameters.get("IdpSelfDomain");
        federatedDomain = federatedDomain.trim().toUpperCase();

        if (selfDomain != null && selfDomain.trim().toUpperCase().equals(federatedDomain)) {
            return null;
        }

        fedeartedIdp = cachedIdps.get(federatedDomain);

        if (fedeartedIdp == null) {
            fedeartedIdp = AACIdpProperties.getProperty(federatedDomain);
        }

        if (log.isDebugEnabled()) {
            log.debug("Federated domain : " + fedeartedIdp);
        }

        if (fedeartedIdp != null) {
            cachedIdps.put(federatedDomain, fedeartedIdp);
        }

        return fedeartedIdp;
    }

    /**
     * Gets the login page URL that needs to be filtered.
     *
     * @return login page URL.
     */
    public static String getLoginPage() {
        return loginPage;
    }

    /**
     * Returns the landing page to which the login requests will be redirected to.
     *
     * @return URL of the landing page
     */
    public static String getLandingPage() {
        return landingPage;
    }

    /**
     * Returns the external logout page url, to which user-agent is redirected
     * after invalidating the local carbon session
     *
     * @return
     */
    public static String getExternalLogoutPage() {
        return externalLogoutPage;
    }

    /**
     * Returns whether IDP supported for logout or not
     * used while redirecting to external logout page
     * @return
     */
    public static boolean isLogoutSupportedIDP() {
        return logoutSupportedIDP;
    }

    /**
     * Returns the login attribute name which use to get the username from the OAUTH2 Response.
     *
     * @return Name of the login attribute
     */
    public static String getLoginAttributeName() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return parameters.get(OAUTH2SSOAuthenticatorConstants.USER_NAME_FIELD);
    }
    
    /**
     * Returns the default tenant containing the created users if there is no provided provision tenant.
     *
     * @return Name of the login attribute
     */
    public static String getTenantDefault() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return parameters.get(OAUTH2SSOAuthenticatorConstants.TENANT_DEFAULT);
    }

	/**
     * Returns the list of the scopes that specify the level of access that the application is requesting regarding userinfo API
     * 
     * @return 
     */
    public static String getScopesListUserInfo() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return scopesListUserInfo;
    }
    
    /**
     * Returns the URL of the endpoint to access the API of roles informations
     * 
     * @return 
     */
    public static String getApiRoleInfoUrl() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return apiRoleInfoUrl;
    }
    
    /**
     * Returns the URL of the endpoint to access the API of roles informations
     * 
     * @return 
     */
    public static String getOauthProviderName() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return parameters.get(OAUTH2SSOAuthenticatorConstants.OAUTH_PROVIDER_NAME);
    }
    
    /**
     * Returns the URL of the endpoint to access the API of user informations
     * 
     * @return 
     */
    public static String getApiUserInfoUrl() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return apiUserInfoUrl;
    }
    
    /**
     * Returns the URL to check the validity of the generated access_token
     * 
     * @return 
     */
    public static String getCheckTokenEndpoiuntUrl() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return checkTokenEndpoiuntUrl;
    }
    
    /**
     * Returns the URL  to get the access_token 
     * 
     * @return 
     */
    public static String getTokenUrl() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return tokenUrl;
    }
    
    /**
     * Returns the logoutUrl 
     * 
     * @return 
     */
    public static String getAuthorizationUrl() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return authorizationUrl;
    }
    
    /**
     * Returns the logoutUrl 
     * 
     * @return 
     */
    public static String getLogoutUrl() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return logoutUrl;
    }
    
    /**
     * Returns the redirectUrl which is the callback URL if the authorization ends up successfully 
     * 
     * @return 
     */
    public static String getRedirectUrl() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return redirectUrl;
    }
    
	/**
     * Returns the clientSecret generated from console.developers.google.com Credentials panel
     * 
     * @return 
     */
    public static String getClientSecret() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return clientSecret;
    }
    /**
     * Returns the clientId generated from console.developers.google.com Credentials panel
     * 
     * @return 
     */
    public static String getClientId() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return clientId;
    }

    /**
     * Returns the response if the tenant should be created or not
     *
     * @return Name of the login attribute
     */
    public static String getTenantProvisioningEnabled() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return parameters.get(OAUTH2SSOAuthenticatorConstants.TENANT_PROVISIONING_ENABLED);
    }
    
    /**
     * Returns the value of the ROLE PREFIX if specified in the authenticators config file
     * otherwise it puts the hardcoded value
     *
     * @return Name of the login attribute
     */
    public static String getRoleSpace() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        if (parameters.get(OAUTH2SSOAuthenticatorConstants.ROLE_SPACE) != null) {
            return parameters.get(OAUTH2SSOAuthenticatorConstants.ROLE_SPACE);
        }
        return parameters.get(OAUTH2SSOAuthenticatorConstants.ROLE_SPACE_VALUE);
    }
    
    /**
     * Returns the value of the ROLE PREFIX if specified in the authenticators config file
     * otherwise it puts the hardcoded value
     *
     * @return Name of the login attribute
     */
    public static String getRoleContext() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        if (parameters.get(OAUTH2SSOAuthenticatorConstants.ROLE_CONTEXT) != null) {
            return parameters.get(OAUTH2SSOAuthenticatorConstants.ROLE_CONTEXT);
        }
        return parameters.get(OAUTH2SSOAuthenticatorConstants.ROLE_CONTEXT_VALUE);
    }
    
    /**
     * Returns the value of SELECT_TENANT_URL if specified in the authenticators config file
     *
     * @return URL of the JSP page for tenant selection
     */
    public static String getSelectTenantUrl() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return selectTenantUrl;
    }
    
    /**
     * Returns the value of the TENANT_SELECTED_URL if specified in the authenticators config file
     *
     * @return URL to redirect the browser to after tenant has been selected
     */
    public static String getTenantSelectedUrl() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return tenantSelectedUrl;
    }
    
    public static boolean isProvider (String roleName, String context) {
    	boolean isProvider = false;
    	String definedContext = Util.getRoleContext();
    	if(context != null && context.equals(definedContext) 
    			&& roleName.equals(OAUTH2SSOAuthenticatorConstants.ROLE_PROVIDER)) {
    		isProvider = true;
    	}
    	return isProvider;
    }
    /**
     * Handle malformed Responses.
     *
     * @param req      HttpServletRequest
     * @param resp     HttpServletResponse
     * @param errorMsg Error message to be displayed in HttpServletResponse.jsp
     * @throws IOException Error when redirecting
     */
    public static void handleMalformedResponses(HttpServletRequest req, HttpServletResponse resp, String errorMsg) throws IOException {
        HttpSession session = req.getSession();
        session.setAttribute(OAUTH2SSOAuthenticatorConstants.NOTIFICATIONS_ERROR_MSG, errorMsg);
        resp.sendRedirect(getAdminConsoleURL(req) + "oauth2-sso-acs/notifications.jsp?error="+errorMsg);
        return;
    }
    /**
     * Get the admin console url from the request.
     *
     * @param request httpServletReq that hits the ACS Servlet
     * @return Admin Console URL
     */
    public static  String getAdminConsoleURL(HttpServletRequest request) {
        String url = CarbonUIUtil.getAdminConsoleURL(request);
        if (!url.endsWith("/")) {
            url = url + "/";
        }
        if (url.indexOf("/oauth2_acs") != -1) {
            url = url.replace("/oauth2_acs", "");
        }
        if (url.indexOf("/forwardtenant") != -1) {
            url = url.replace("/forwardtenant", "");
        }
        return url;
    }
}
