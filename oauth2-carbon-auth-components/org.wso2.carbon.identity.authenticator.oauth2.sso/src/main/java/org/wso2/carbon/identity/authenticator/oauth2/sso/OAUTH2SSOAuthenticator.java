
package org.wso2.carbon.identity.authenticator.oauth2.sso;

import org.apache.axis2.context.MessageContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.util.tracker.ServiceTracker;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.security.AuthenticatorsConfiguration;
import org.wso2.carbon.core.services.authentication.CarbonServerAuthenticator;
import org.wso2.carbon.core.services.util.CarbonAuthenticationUtil;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.core.util.PermissionUpdateUtil;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.OAUTH2SSOAuthenticatorConstants;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.Util;
import org.wso2.carbon.identity.authenticator.oauth2.sso.dto.AuthnReqDTO;
import org.wso2.carbon.identity.authenticator.oauth2.sso.internal.OAUTH2SSOAuthBEDataHolder;
import org.wso2.carbon.identity.authenticator.oauth2.sso.tenant.TenantServiceClient;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.AuthenticationObserver;
import org.wso2.carbon.utils.ServerConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class OAUTH2SSOAuthenticator implements CarbonServerAuthenticator {

    public static final Log log = LogFactory.getLog(OAUTH2SSOAuthenticator.class);
    private static final Log AUDIT_LOG = CarbonConstants.AUDIT_LOG;

    private OAUTH2SSOAuthBEDataHolder dataHolder = OAUTH2SSOAuthBEDataHolder.getInstance();

    private static final int DEFAULT_PRIORITY_LEVEL = 3;
    private static final String AUTHENTICATOR_NAME = OAUTH2SSOAuthenticatorConstants.AUTHENTICATOR_NAME;
    private SecureRandom random = new SecureRandom();
    private TenantServiceClient tenantClient;
    private boolean isAdmin = false;

    public boolean login(AuthnReqDTO authDto) {
        String username = null;
        String tenantDomain = Util.getTenantDefault(); // It is supposed that this tenant already exists
        String auditResult = OAUTH2SSOAuthenticatorConstants.AUDIT_RESULT_FAILED;
        try {
        	
	        HttpSession httpSession = getHttpSession();
            String authResponse = authDto.getResponse();
            isAdmin = authDto.getIsAdmin();
            log.info("tenant from ui: "+authDto.getTenant()+" isAdmin: "+isAdmin);

            username = authResponse;
            if (StringUtils.isBlank(username)) {
                log.error("Authentication Request is rejected. " +
                        "AACResponse does not contain the username of the subject.");
                CarbonAuthenticationUtil.onFailedAdminLogin(httpSession, "", -1,
                        "AAC SSO Authentication", "AACResponse does not contain the username of the subject");
                // Unable to call #handleAuthenticationCompleted since there is no way to determine
                // tenantId without knowing the username.
                return false;
            }

            log.info("response from AACSSOUI : "+username);
            RegistryService registryService = dataHolder.getRegistryService();
            RealmService realmService = dataHolder.getRealmService();
            tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);

            handleAuthenticationStarted(tenantId);

            username = MultitenantUtils.getTenantAwareUsername(username);
            UserRealm realm = AnonymousSessionUtil.getRealmByTenantDomain(registryService,
                    realmService, tenantDomain);
            // Authentication is done

            // Starting user provisioning
            provisionUser(username, realm, authResponse);
            // End user provisioning

            // Starting Authorization

            PermissionUpdateUtil.updatePermissionTree(tenantId);
            boolean isAuthorized = false;
            if (realm != null) {
                isAuthorized = realm.getAuthorizationManager().isUserAuthorized(username,
                        "/permission/admin/login", CarbonConstants.UI_PERMISSION_ACTION);
            }
            if (isAuthorized) {
                UserCoreUtil.setDomainInThreadLocal(null);
                CarbonAuthenticationUtil.onSuccessAdminLogin(httpSession, username,
                        tenantId, tenantDomain, "OAUTH2 SSO Authentication");
                handleAuthenticationCompleted(tenantId, true);
                auditResult = OAUTH2SSOAuthenticatorConstants.AUDIT_RESULT_SUCCESS;
                return true;
            } else {
                log.error("Authentication Request is rejected. Authorization Failure.");
                CarbonAuthenticationUtil.onFailedAdminLogin(httpSession, username, tenantId,
                        "OAUTH2 SSO Authentication", "Authorization Failure");
                handleAuthenticationCompleted(tenantId, false);
                return false;
            }
        } catch (Exception e) {
            String msg = "System error while Authenticating/Authorizing User : " + e.getMessage();
            log.error(msg, e);
            return false;
        } finally {
            if (username != null && username.trim().length() > 0 && AUDIT_LOG.isInfoEnabled()) {

                String auditInitiator = username + UserCoreConstants.TENANT_DOMAIN_COMBINER + tenantDomain;
                String auditData = "";

                AUDIT_LOG.info(String.format(OAUTH2SSOAuthenticatorConstants.AUDIT_MESSAGE,
                        auditInitiator, OAUTH2SSOAuthenticatorConstants.AUDIT_ACTION_LOGIN, AUTHENTICATOR_NAME,
                        auditData, auditResult));
            }
        }
    }

    private void handleAuthenticationStarted(int tenantId) {
        BundleContext bundleContext = dataHolder.getBundleContext();
        if (bundleContext != null) {
            ServiceTracker tracker = new ServiceTracker(bundleContext, AuthenticationObserver.class.getName(), null);
            tracker.open();
            Object[] services = tracker.getServices();
            if (services != null) {
                for (Object service : services) {
                    ((AuthenticationObserver) service).startedAuthentication(tenantId);
                }
            }
            tracker.close();
        }
    }

    private void handleAuthenticationCompleted(int tenantId, boolean isSuccessful) {
        BundleContext bundleContext = dataHolder.getBundleContext();
        if (bundleContext != null) {
            ServiceTracker tracker = new ServiceTracker(bundleContext, AuthenticationObserver.class.getName(), null);
            tracker.open();
            Object[] services = tracker.getServices();
            if (services != null) {
                for (Object service : services) {
                    ((AuthenticationObserver) service).completedAuthentication(
                            tenantId, isSuccessful);
                }
            }
            tracker.close();
        }
    }

    public void logout() {
        String loggedInUser;
        String delegatedBy;
        Date currentTime = Calendar.getInstance().getTime();
        SimpleDateFormat date = new SimpleDateFormat("'['yyyy-MM-dd HH:mm:ss,SSSS']'");
        HttpSession session = getHttpSession();

        if (session != null) {
            loggedInUser = (String) session.getAttribute(ServerConstants.USER_LOGGED_IN);
            delegatedBy = (String) session.getAttribute("DELEGATED_BY");

            if (StringUtils.isNotBlank(loggedInUser)) {
                String logMessage = "'" + loggedInUser + "' logged out at " + date.format(currentTime);

                if (delegatedBy != null) {
                    logMessage += " delegated by " + delegatedBy;
                }

                log.info(logMessage);
            }

            session.invalidate();

            if (loggedInUser != null && AUDIT_LOG.isInfoEnabled()) {
                // username in the session is in tenantAware manner
                String tenantAwareUsername = loggedInUser;
                String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();

                String auditInitiator = tenantAwareUsername + UserCoreConstants.TENANT_DOMAIN_COMBINER + tenantDomain;
                String auditData = delegatedBy != null ? "Delegated By : " + delegatedBy : "";

                AUDIT_LOG.info(String.format(OAUTH2SSOAuthenticatorConstants.AUDIT_MESSAGE,
                        auditInitiator, OAUTH2SSOAuthenticatorConstants.AUDIT_ACTION_LOGOUT, AUTHENTICATOR_NAME,
                        auditData, OAUTH2SSOAuthenticatorConstants.AUDIT_RESULT_SUCCESS));
            }
        }
    }

    public boolean isHandle(MessageContext messageContext) {
        return true;
    }

    public boolean isAuthenticated(MessageContext messageContext) {
        HttpServletRequest request = (HttpServletRequest) messageContext
                .getProperty(HTTPConstants.MC_HTTP_SERVLETREQUEST);
        HttpSession httpSession = request.getSession();
        String loginStatus = (String) httpSession.getAttribute(ServerConstants.USER_LOGGED_IN);

        return (loginStatus != null);
    }

    public boolean authenticateWithRememberMe(MessageContext messageContext) {
        return false;
    }

    public int getPriority() {
        AuthenticatorsConfiguration authenticatorsConfiguration = AuthenticatorsConfiguration.getInstance();
        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig =
                authenticatorsConfiguration.getAuthenticatorConfig(AUTHENTICATOR_NAME);
        if (authenticatorConfig != null && authenticatorConfig.getPriority() > 0) {
            return authenticatorConfig.getPriority();
        }
        return DEFAULT_PRIORITY_LEVEL;
    }

    public String getAuthenticatorName() {
        return AUTHENTICATOR_NAME;
    }

    public boolean isDisabled() {
        AuthenticatorsConfiguration authenticatorsConfiguration = AuthenticatorsConfiguration.getInstance();
        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig =
                authenticatorsConfiguration.getAuthenticatorConfig(AUTHENTICATOR_NAME);
        if (authenticatorConfig != null) {
            return authenticatorConfig.isDisabled();
        }
        return false;
    }

    
    /**
     * Provision/Create user on the server(SP) and update roles accordingly
     *
     * @param username
     * @param realm
     * @param xmlObject
     * @throws Exception 
     * @throws AACSSOAuthenticatorException
     */
    private void provisionUser(String username, UserRealm realm, String aacResp) throws Exception {
    	try {
	        AuthenticatorsConfiguration authenticatorsConfiguration = AuthenticatorsConfiguration.getInstance();
	        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig =
	                authenticatorsConfiguration.getAuthenticatorConfig(AUTHENTICATOR_NAME);
	
	        if (authenticatorConfig != null) {
	            Map<String, String> configParameters = authenticatorConfig.getParameters();
	
	            boolean isJITProvisioningEnabled = false;
	            if (configParameters.containsKey(OAUTH2SSOAuthenticatorConstants.JIT_USER_PROVISIONING_ENABLED)) {
	                isJITProvisioningEnabled = Boolean.parseBoolean(configParameters.get(OAUTH2SSOAuthenticatorConstants.JIT_USER_PROVISIONING_ENABLED));
	            }
	
	            if (isJITProvisioningEnabled) {
	                String userstoreDomain = null;
	                if (configParameters.containsKey(OAUTH2SSOAuthenticatorConstants.PROVISIONING_DEFAULT_USERSTORE)) {
	                    userstoreDomain = configParameters.get(OAUTH2SSOAuthenticatorConstants.PROVISIONING_DEFAULT_USERSTORE);
	                }
	
	                UserStoreManager userstore = null;
	
	                // TODO : Get userstore from asserstion
	                // TODO : remove user store domain name from username
	
	                if (userstoreDomain != null && !userstoreDomain.isEmpty()) {
	                    userstore = realm.getUserStoreManager().getSecondaryUserStoreManager(userstoreDomain);
	                }
	
	                // If default user store is invalid or not specified use primary user store
	                
	            	if (userstore == null) {
	            		userstore = realm.getUserStoreManager();
	            	}
	                String[] newRoles = getRoles(configParameters);
	                if (newRoles == null) {
	                    newRoles = new String[]{};
	                }	
	                if (log.isDebugEnabled()) {
	                    log.debug("User " + username + " contains roles : " + Arrays.toString(newRoles) + " as per response and (default role) config");
	                }
	
	                // addingRoles = newRoles AND allExistingRoles
	                Collection<String> addingRoles = new ArrayList<String>();
	                Collections.addAll(addingRoles, newRoles);
	                Collection<String> allExistingRoles = Arrays.asList(userstore.getRoleNames());
	                addingRoles.retainAll(allExistingRoles);
	
	                if (userstore.isExistingUser(username)) {
	                    // Update user
	                    Collection<String> currentRolesList = Arrays.asList(userstore.getRoleListOfUser(username));
	                    // addingRoles = (newRoles AND existingRoles) - currentRolesList)
	                    addingRoles.removeAll(currentRolesList);
	
	
	                    Collection<String> deletingRoles = new ArrayList<String>();
	                    deletingRoles.addAll(currentRolesList);
	                    // deletingRoles = currentRolesList - newRoles
	                    deletingRoles.removeAll(Arrays.asList(newRoles));
	
	                    // Exclude Internal/everyonerole from deleting role since its cannot be deleted
	                    deletingRoles.remove(realm.getRealmConfiguration().getEveryOneRoleName());
	
	                    // Check for case whether superadmin login
	                    if (userstore.getRealmConfiguration().isPrimary() && username.equals(realm.getRealmConfiguration().getAdminUserName())) {
	                        boolean isSuperAdminRoleRequired = false;
	                        if (configParameters.containsKey(OAUTH2SSOAuthenticatorConstants.IS_SUPER_ADMIN_ROLE_REQUIRED)) {
	                            isSuperAdminRoleRequired = Boolean.parseBoolean(configParameters.get(OAUTH2SSOAuthenticatorConstants.IS_SUPER_ADMIN_ROLE_REQUIRED));
	                        }
	
	                        // Whether superadmin login without superadmin role is permitted
	                        if (!isSuperAdminRoleRequired && deletingRoles.contains(realm.getRealmConfiguration().getAdminRoleName())) {
	                            // Avoid removing superadmin role from superadmin user.
	                            deletingRoles.remove(realm.getRealmConfiguration().getAdminRoleName());
	                            log.warn("Proceeding with allowing super admin to be logged in, eventhough response doesn't include superadmin role assiged for the superadmin user.");
	                        }
	                    }
	
                        log.info("Deleting roles : " + Arrays.toString(deletingRoles.toArray(new String[0])) + " and Adding roles : " + Arrays.toString(addingRoles.toArray(new String[0])));
	                    userstore.updateRoleListOfUser(username, deletingRoles.toArray(new String[0]), addingRoles.toArray(new String[0]));
                        log.info("User: " + username + " is updated via AAC authenticator with roles : " + Arrays.toString(newRoles));
	                } else {   
	                	log.info("User: " + username + " is provisioned via AAC authenticator with roles : " + Arrays.toString(addingRoles.toArray(new String[0])));
	                	userstore.addUser(username, generatePassword(), addingRoles.toArray(new String[0]), null, null);
	                    realm.getAuthorizationManager().authorizeUser(username, "/permission/admin/login", CarbonConstants.UI_PERMISSION_ACTION);
                        	                }
	            } else {
	                if (log.isDebugEnabled()) {
	                    log.debug("User provisioning disabled");
	                }
	            }
	        } else {
	            if (log.isDebugEnabled()) {
	                log.debug("Cannot find authenticator config for authenticator : " + AUTHENTICATOR_NAME);
	            }
	            throw new Exception("Cannot find authenticator config for authenticator : " + AUTHENTICATOR_NAME);
	        }
    	}catch(Exception e ) {
        	log.error("Error provisioning user: "+e);
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

    
    private HttpSession getHttpSession() {
        MessageContext msgCtx = MessageContext.getCurrentMessageContext();
        HttpSession httpSession = null;
        if (msgCtx != null) {
            HttpServletRequest request =
                    (HttpServletRequest) msgCtx.getProperty(HTTPConstants.MC_HTTP_SERVLETREQUEST);
            httpSession = request.getSession();
        }
        return httpSession;
    }
    
    /**
     * Get roles from the AAC Object to define the level of permissions inside DSS
     *
     * @return String array of roles
     */
    private String[] getRoles(Map<String, String> configParameters) {
    	
    	String[] arrRoles = new String [1];
    	//TODO to be used when defining the roles/permissions in AAC
    	
//    	if (configParameters.containsKey(OAUTH2SSOAuthenticatorConstants.PROVISIONING_DEFAULT_ROLE)
//    			&& configParameters.get(OAUTH2SSOAuthenticatorConstants.PROVISIONING_DEFAULT_ROLE) != null
//    			&& !configParameters.get(OAUTH2SSOAuthenticatorConstants.PROVISIONING_DEFAULT_ROLE).isEmpty() ) 
//    	{
//    		arrRoles[0] = configParameters.get(OAUTH2SSOAuthenticatorConstants.PROVISIONING_DEFAULT_ROLE);
//        }
        arrRoles[0] = "";
    	if(isAdmin) {
    		arrRoles[0]= "admin";
    	}
        return arrRoles;
    }
}