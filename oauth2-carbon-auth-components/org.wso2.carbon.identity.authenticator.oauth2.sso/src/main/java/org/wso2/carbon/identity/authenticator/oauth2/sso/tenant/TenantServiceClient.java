package org.wso2.carbon.identity.authenticator.oauth2.sso.tenant;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.tenant.mgt.stub.TenantMgtAdminServiceStub;
import org.wso2.carbon.tenant.mgt.stub.beans.xsd.TenantInfoBean;
import org.wso2.carbon.utils.CarbonUtils;

public class TenantServiceClient {
	
	private static final Log log = LogFactory.getLog(TenantServiceClient.class);
	private static final int TIMEOUT_IN_MILLIS = 15 * 60 * 1000;

    private TenantMgtAdminServiceStub stub;

    public TenantServiceClient(String backendServerURL, String username, String password) throws Exception {

        String epr = backendServerURL + "/services/" + "TenantMgtAdminService";

        try { 
        	stub = new TenantMgtAdminServiceStub(epr);
    	    CarbonUtils.setBasicAccessSecurityHeaders(username, password, true, stub._getServiceClient());
    	    ServiceClient serviceClient = stub._getServiceClient();
    	    Options option = serviceClient.getOptions();  
    	    option.setManageSession(true);  
    	    option.setTimeOutInMilliSeconds(TIMEOUT_IN_MILLIS);
    		option.setProperty(HTTPConstants.SO_TIMEOUT, TIMEOUT_IN_MILLIS);
    		option.setProperty(HTTPConstants.CONNECTION_TIMEOUT, TIMEOUT_IN_MILLIS);
    		option.setCallTransportCleanup(true);
    		option.setManageSession(true);
            
        } catch (AxisFault axisFault) {
            String msg = "Failed to initiate TenantMgtAdminService service client. " + axisFault.getMessage();
            log.error(msg, axisFault);
            throw new Exception(msg, axisFault);
        }
    }

    public void addTenant(TenantInfoBean tenantInfoBean) throws Exception {
        stub.addTenant(tenantInfoBean);
    }

    public TenantInfoBean[] retrieveTenants() throws Exception {
        return stub.retrieveTenants();
    }
    
    public TenantInfoBean getTenant(String domainName) throws Exception {
        return stub.getTenant(domainName);
    }

    public void updateTenant(TenantInfoBean tenantInfoBean) throws Exception {
        stub.updateTenant(tenantInfoBean);
    }

    public void activateTenant(String domainName) throws Exception {
        stub.activateTenant(domainName);
    }

    public void deactivateTenant(String domainName) throws Exception {
        stub.deactivateTenant(domainName);
    }

}
