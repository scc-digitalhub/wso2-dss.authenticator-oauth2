package org.wso2.carbon.identity.authenticator.oauth2.sso.ui.authenticator;

import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.common.AuthenticationException;
import org.wso2.carbon.core.security.AuthenticatorsConfiguration;
import org.wso2.carbon.core.services.util.CarbonAuthenticationUtil;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.client.OAUTH2SSOAuthenticationClient;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.internal.OAUTH2SSOAuthFEDataHolder;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.session.SSOSessionManager;
import org.wso2.carbon.tenant.mgt.stub.beans.xsd.TenantInfoBean;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.OAUTH2SSOAuthenticatorConstants;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.Util;
import org.wso2.carbon.identity.authenticator.oauth2.sso.tenant.TenantServiceClient;
import org.wso2.carbon.ui.AbstractCarbonUIAuthenticator;
import org.wso2.carbon.ui.CarbonSSOSessionManager;
import org.wso2.carbon.ui.CarbonUIUtil;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ServerConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.Map;
import java.util.Properties;

public class OAUTH2SSOUIAuthenticator extends AbstractCarbonUIAuthenticator {

    public static final Log log = LogFactory.getLog(OAUTH2SSOUIAuthenticator.class);
    private static final Log AUDIT_LOG = CarbonConstants.AUDIT_LOG;
    private TenantServiceClient tenantClient;
    private static final int DEFAULT_PRIORITY_LEVEL = 50;
    private static final String AUTHENTICATOR_NAME = "OAUTH2SSOUIAuthenticator";
    private OAUTH2SSOAuthFEDataHolder dataHolder = OAUTH2SSOAuthFEDataHolder.getInstance();
    private boolean isAdmin = false;
    private SecureRandom random = new SecureRandom();
    String backEndServerURL;

    public boolean canHandle(HttpServletRequest request) {
        Object OAUTH2CodeState = request.getParameter(OAUTH2SSOAuthenticatorConstants.OAUTH2_AUTH_CODE_STATE);
        // if it is a logout request
        if (request.getRequestURI().indexOf("/carbon/admin/logout_action.jsp") > -1) {
            return true;
        }
        // in case of a login request, check for OAUTH2CodeState
        if (OAUTH2CodeState != null) {
            return true;
        }
        return false;
    }

    public void authenticate(HttpServletRequest request) throws AuthenticationException {
        boolean isAuthenticated = false;
        String auditResult = OAUTH2SSOAuthenticatorConstants.AUDIT_RESULT_FAILED;
        regenerateSession(request);

        HttpSession session = request.getSession();
        ServletContext servletContext = request.getSession().getServletContext();
        Object OAUTH2Response =  request.getAttribute(OAUTH2SSOAuthenticatorConstants.LOGGED_IN_USER);
        String tenantDomain = (String) request.getAttribute(OAUTH2SSOAuthenticatorConstants.HTTP_POST_PARAM_OAUTH2_ROLES);
        isAdmin = (boolean)request.getAttribute(OAUTH2SSOAuthenticatorConstants.IS_ADMIN);
        String username = (String) OAUTH2Response;
        backEndServerURL = request.getParameter("backendURL");
        if (backEndServerURL == null) {
            backEndServerURL = CarbonUIUtil.getServerURL(servletContext, session);
        }
        request.getSession().setAttribute(CarbonConstants.SERVER_URL, backEndServerURL);
        servletContext = request.getSession().getServletContext();
        ConfigurationContext configContext = (ConfigurationContext) servletContext.getAttribute(
                CarbonConstants.CONFIGURATION_CONTEXT);
        
        String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_AUTH_TOKEN);

        // authorize the user with the back-end
        OAUTH2SSOAuthenticationClient authenticationClient = null;
        try {
            if (log.isDebugEnabled()) {
                log.debug("Invoking the OAUTH2 SSO Authenticator BE for the Response : " + tenantDomain);
            }
            
            boolean checkTenant = handleTenant(username,request.getSession());
//            if(!checkTenant) {
//            	throw new Exception("The domain has not yet been created by the provider");
//            }
            authenticationClient = new OAUTH2SSOAuthenticationClient(
                    configContext, backEndServerURL, cookie, request.getSession());
            isAuthenticated = authenticationClient.login(tenantDomain, username, isAdmin);

            // add an entry to CarbonSSOSessionManager : IdpSessionIndex --> localSessionId
            if (isAuthenticated) {
                CarbonSSOSessionManager ssoSessionManager =
                        OAUTH2SSOAuthFEDataHolder.getInstance().getCarbonSSOSessionManager();
                String sessionId = getSessionIndexFromResponse(OAUTH2Response,request);
                if (sessionId != null) {
                    // Session id is provided only when Single Logout enabled at the IdP.
                    ssoSessionManager.addSessionMapping(sessionId,session.getId());
                    request.getSession().setAttribute(OAUTH2SSOAuthenticatorConstants.IDP_SESSION_INDEX, sessionId);
                    SSOSessionManager.getInstance().addSession(sessionId, request.getSession());
                }
                onSuccessAdminLogin(request, username);
                auditResult = OAUTH2SSOAuthenticatorConstants.AUDIT_RESULT_SUCCESS;
            } else {
                log.error("Authentication failed.");
            }
        } catch (Exception e) {
            log.error("Error when authenticating the user : " + username, e);
            throw new AuthenticationException("Error when authenticating the user : " + username, e);
        } 
        if (username != null && username.trim().length() > 0 && AUDIT_LOG.isInfoEnabled()) {
            String auditInitiator = username + UserCoreConstants.TENANT_DOMAIN_COMBINER + tenantDomain;
            String auditData = "";

            AUDIT_LOG.info(String.format(OAUTH2SSOAuthenticatorConstants.AUDIT_MESSAGE,
                    auditInitiator, OAUTH2SSOAuthenticatorConstants.AUDIT_ACTION_LOGIN, AUTHENTICATOR_NAME,
                    auditData, auditResult));
        }
        if (!isAuthenticated) {
            throw new AuthenticationException("Authentication failure " + username);
        }
    }

    public void unauthenticate(Object o) throws Exception {
        String auditResult = OAUTH2SSOAuthenticatorConstants.AUDIT_RESULT_FAILED;
        HttpServletRequest request = null;
        HttpSession session = null;

        if (o instanceof HttpSession) {
            session = (HttpSession) o;
        } else {
            request = (HttpServletRequest) o;
            session = request.getSession();
        }

        String username = (String) session.getAttribute(CarbonConstants.LOGGED_USER);
        ServletContext servletContext = session.getServletContext();
        ConfigurationContext configContext = (ConfigurationContext) servletContext
                .getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);

        String backendServerURL = CarbonUIUtil.getServerURL(servletContext, session);
        try {
            String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_AUTH_TOKEN);
            OAUTH2SSOAuthenticationClient authClient = new OAUTH2SSOAuthenticationClient(configContext,
                    backendServerURL,
                    cookie,
                    session);
            authClient.logout(session);

//        // memory cleanup : remove the invalid session from the invalid session list at the SSOSessionManager
//        CarbonSSOSessionManager ssoSessionManager =
//                    OAUTH2SSOAuthFEDataHolder.getInstance().getCarbonSSOSessionManager();
//        ssoSessionManager.removeInvalidSession(session.getId());

            if (request != null) {
                // this attribute is used to avoid generate the logout request
                request.setAttribute(OAUTH2SSOAuthenticatorConstants.HTTP_ATTR_IS_LOGOUT_REQ, Boolean.valueOf(true));
                request.setAttribute(OAUTH2SSOAuthenticatorConstants.LOGGED_IN_USER, session.getAttribute(
                        "logged-user"));

                if(!Util.isLogoutSupportedIDP()) {
                    request.setAttribute(OAUTH2SSOAuthenticatorConstants.EXTERNAL_LOGOUT_PAGE, Util.getExternalLogoutPage());
                }
            }

            auditResult = OAUTH2SSOAuthenticatorConstants.AUDIT_RESULT_SUCCESS;

            if(username != null && !"".equals(username.trim())
                    && request != null && "true".equalsIgnoreCase(request.getParameter("logoutcomplete"))) {

                if(session.getAttribute("tenantDomain") != null) {
                    // Build username for authorized user login
                    // username in the session is in tenantAware manner
                    username = username + UserCoreConstants.TENANT_DOMAIN_COMBINER
                            + PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
                } else {
                    // Keep same username for unauthorized user login
                }

                log.info(username + " successfully logged out");
            }
        } catch (Exception ignored) {
            String msg = "Configuration context is null.";
            log.error(msg);
            throw new Exception(msg);
        } finally {
            if (username != null && username.trim().length() > 0 && AUDIT_LOG.isInfoEnabled()
                    && request != null && "true".equalsIgnoreCase(request.getParameter("logoutcomplete"))) {
                // use the username built above (when printing info log)
                String auditInitiator = username;
                String auditData = "";

                AUDIT_LOG.info(String.format(OAUTH2SSOAuthenticatorConstants.AUDIT_MESSAGE,
                        auditInitiator, OAUTH2SSOAuthenticatorConstants.AUDIT_ACTION_LOGOUT, AUTHENTICATOR_NAME,
                        auditData, auditResult));
            }
        }
    }

    public int getPriority() {
        AuthenticatorsConfiguration authenticatorsConfiguration = AuthenticatorsConfiguration.getInstance();
        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig =
                authenticatorsConfiguration.getAuthenticatorConfig(OAUTH2SSOAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (authenticatorConfig != null && authenticatorConfig.getPriority() > 0) {
            return authenticatorConfig.getPriority();
        }
        return DEFAULT_PRIORITY_LEVEL;
    }

    public String getAuthenticatorName() {
        return OAUTH2SSOAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    public boolean isDisabled() {
        AuthenticatorsConfiguration authenticatorsConfiguration = AuthenticatorsConfiguration.getInstance();
        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig =
                authenticatorsConfiguration.getAuthenticatorConfig(OAUTH2SSOAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (authenticatorConfig != null) {
            return authenticatorConfig.isDisabled();
        }
        return false;
    }

    private boolean handleTenant(String username, HttpSession httpSession) throws Exception {
    	int tenantId = 0;
    	 String tenantDomain = Util.getTenantDefault(); // It is supposed that this tenant already exists
    	 boolean tenantProvision = Boolean.parseBoolean(Util.getTenantProvisioningEnabled());
         tenantDomain = MultitenantUtils.getTenantDomain(username);
         if(tenantProvision) {
	            tenantDomain = MultitenantUtils.getTenantDomain(username);
	            tenantId = getTenantId(tenantDomain);
	            log.info("tenant preparation: "+tenantDomain+" "+tenantId);
	            String user = MultitenantUtils.getTenantAwareUsername(username);
	            tenantId = provisionTenant(user, tenantDomain, tenantId);
	            if(tenantId == 0) { // Tenant can not be created if the role is not provider
	            	CarbonAuthenticationUtil.onFailedAdminLogin(httpSession, "", -1,
	                        "AAC SSO Authentication:The domain has not yet been creted by the provider.", "The domain has not yet been creted by the provider.");
	                return false;
	            }
         }
         return true;
    }
    
    /**
     * Provision/Create tenant on the server(SP) 
     *
     * @param username
     * @param realm
     * @param xmlObject
     * @throws org.wso2.carbon.user.api.UserStoreException 
     * @throws Exception 
     * @throws AACSSOAuthenticatorException
     */
    private int provisionTenant(String username, String tenantDomain, int tenantId) throws Exception {
    	try {
	    	TenantInfoBean tenantInfoBean = new TenantInfoBean();
	    	if(tenantId == 0 && isAdmin) {
	    		tenantInfoBean.setAdmin("admin");
	            tenantInfoBean.setFirstname("firstname");
	            tenantInfoBean.setLastname("lastname");
	            tenantInfoBean.setAdminPassword(generatePassword());
	            tenantInfoBean.setTenantDomain(tenantDomain);
	            tenantInfoBean.setEmail(username);
	            tenantInfoBean.setCreatedDate(Calendar.getInstance());
	            getTenantClient().addTenant(tenantInfoBean);
	            tenantId = tenantClient.getTenant(tenantDomain).getTenantId();
	    	}
			return tenantId;
    	}catch(Exception e) {
    		log.info("Error provisioning tenant: " + e.getMessage());
    		return 0;
    	}
    }
    
    /**
     * 
     */
    private int getTenantId(String tenantDomain) throws Exception {
       int tenantId = getTenantClient().getTenant(tenantDomain).getTenantId();
               return tenantId;
    }

    
    /**
     * Create Tenant Client instance
     * @return
     * @throws Exception
     */
    private TenantServiceClient getTenantClient() throws Exception {
    	try {
	    	log.info("backend URL: "+backEndServerURL);
	    	if( tenantClient== null) {
	    		RealmService realmService = dataHolder.getRealmService();
	            RealmConfiguration realmConfig = realmService.getBootstrapRealmConfiguration();
	            String adminUser = realmConfig.getAdminUserName();
	            String adminPassw = realmConfig.getAdminPassword();
	    		tenantClient = new TenantServiceClient(backEndServerURL, adminUser, adminPassw) ;
	    	}
	    	return tenantClient;
    	}catch(Exception e) {
    		log.info("Problem inside getTenantClient:  " + e.getMessage());
    		return tenantClient;
    	}
    	
    }
    /**
     * Generates (random) password for user to be provisioned
     *
     * @param username
     * @return
     */
    private String generatePassword() {
        return  new BigInteger(130, random).toString(32);
    }
        /**
     * Read the session index from a Response
     * @param response OAUTH2 Response
     * @return Session Index value contained in the Response
     */
    private String getSessionIndexFromResponse(Object response,HttpServletRequest req) {
        String sessionIndex = (String) req.getSession().getAttribute(OAUTH2SSOAuthenticatorConstants.IDP_SESSION_INDEX);
       return sessionIndex;
    }

    /**
     * Regenerates session id after each login attempt.
     *
     * @param request
     */
    private void regenerateSession(HttpServletRequest request) {

        HttpSession oldSession = request.getSession();

        Enumeration attrNames = oldSession.getAttributeNames();
        Properties props = new Properties();

        while (attrNames != null && attrNames.hasMoreElements()) {
            String key = (String) attrNames.nextElement();
            props.put(key, oldSession.getAttribute(key));
        }

        oldSession.invalidate();
        HttpSession newSession = request.getSession(true);
        attrNames = props.keys();

        while (attrNames != null && attrNames.hasMoreElements()) {
            String key = (String) attrNames.nextElement();
            newSession.setAttribute(key, props.get(key));
        }
    }

    public boolean reAuthenticateOnSessionExpire(Object object) throws AuthenticationException {
        return false;
    }


    @Override
    public void authenticateWithCookie(HttpServletRequest request)
            throws AuthenticationException {
        // TODO Auto-generated method stub

    }

    @Override
    public String doAuthentication(Object credentials, boolean isRememberMe, ServiceClient client,
                                   HttpServletRequest request) throws AuthenticationException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void handleRememberMe(Map transportHeaders, HttpServletRequest httpServletRequest)
            throws AuthenticationException {
        // TODO Auto-generated method stub

    }
}
