package org.wso2.carbon.identity.authenticator.oauth2.sso.tenant;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Calendar;

import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.services.util.CarbonAuthenticationUtil;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.OAUTH2SSOAuthenticatorConstants;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.Util;
import org.wso2.carbon.identity.authenticator.oauth2.sso.internal.OAUTH2SSOAuthBEDataHolder;
import org.wso2.carbon.tenant.mgt.stub.beans.xsd.TenantInfoBean;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

public class TenantProvision {

	public static final Log log = LogFactory.getLog(TenantProvision.class);
	private TenantServiceClient tenantClient;
	private boolean isAdmin = false;
	private OAUTH2SSOAuthBEDataHolder dataHolder = OAUTH2SSOAuthBEDataHolder.getInstance();
	private SecureRandom random = new SecureRandom();
	private String backEndServerURL;
	private String checkTenantError;
	
	public boolean handleTenant(String username, HttpSession httpSession) throws Exception {
    	int tenantId = 0;
    	boolean tenantIsActive = false;
    	String tenantDomain = Util.getTenantDefault(); // It is supposed that this tenant already exists
    	boolean tenantProvision = Boolean.parseBoolean(Util.getTenantProvisioningEnabled());
        if(tenantProvision) {
	            tenantDomain = MultitenantUtils.getTenantDomain(username);
	            tenantId = getTenantId(tenantDomain);
	            String user = MultitenantUtils.getTenantAwareUsername(username);
	            tenantId = provisionTenant(user, tenantDomain, tenantId);
	            tenantIsActive = getTenantIsActive(tenantDomain);
	            if( !tenantIsActive && tenantId != 0) {
	            	CarbonAuthenticationUtil.onFailedAdminLogin(httpSession, "", -1,
	                        "AAC SSO Authentication:The domain has not been activated by the provider.", "The domain has not been activated by the provider.");
	            	checkTenantError = OAUTH2SSOAuthenticatorConstants.ErrorMessageConstants.RESPONSE_NO_DOMAIN_ACTIVE_BY_PROVIDER_ERROR;
	            	return false;
	            }
	            else if(tenantId == 0) { // Tenant can not be created if the role is not provider
	            	CarbonAuthenticationUtil.onFailedAdminLogin(httpSession, "", -1,
	                        "AAC SSO Authentication:The domain has not yet been created by the provider.", "The domain has not yet been created by the provider.");
	            	checkTenantError = OAUTH2SSOAuthenticatorConstants.ErrorMessageConstants.RESPONSE_NO_DOMAIN_CREATED_BY_PROVIDER_ERROR;
	            	return false;
	            }
         }
         return true;
    }
    
	public void setBackEndURL (String backendUrl) {
		this.backEndServerURL = backendUrl;
	}
	
	public void setIsAdmin (boolean isAdmin) {
		this.isAdmin = isAdmin;
	}
	
	public String getTenantError () {
		return this.checkTenantError;
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
	            tenantInfoBean.setEmail(username.contains("@") ? username : username+"@"+tenantDomain);
	            tenantInfoBean.setCreatedDate(Calendar.getInstance());
	            tenantInfoBean.setActive(true);
	            getTenantClient().addTenant(tenantInfoBean);
	            tenantId = tenantClient.getTenant(tenantDomain).getTenantId();
	    	}else if(tenantDomain.equals("carbon.super")) {
	    		tenantId = -1234;
	    	}
			return tenantId;
    	}catch(Exception e) {
    		return 0;
    	}
    }
    
    /**
     * 
     */
    private int getTenantId(String tenantDomain) throws Exception {
       int tenantId = (tenantDomain.equals("carbon.super") ? -1234 : getTenantClient().getTenant(tenantDomain).getTenantId());
       log.info("Getting the tenant Id: "+tenantId);
       return tenantId;
    }
    
    private boolean getTenantIsActive(String tenantDomain) throws Exception {
        boolean isActive = (tenantDomain.equals("carbon.super") ? true  : getTenantClient().getTenant(tenantDomain).getActive());
        log.info("Getting the tenant active: "+isActive);
        return isActive;
     }
    
    /**
     * Create Tenant Client instance
     * @return
     * @throws Exception
     */
    private TenantServiceClient getTenantClient() throws Exception {
    	try {
	    	if( tenantClient== null) {
	    		RealmService realmService = dataHolder.getRealmService();
	            RealmConfiguration realmConfig = realmService.getBootstrapRealmConfiguration();
	            String adminUser = realmConfig.getAdminUserName();
	            String adminPassw = realmConfig.getAdminPassword();
	    		tenantClient = new TenantServiceClient(backEndServerURL, adminUser, adminPassw) ;
	    	}
	    	return tenantClient;
    	}catch(Exception e) {
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
}
