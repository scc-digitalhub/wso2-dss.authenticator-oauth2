package org.wso2.carbon.identity.authenticator.oauth2.sso.ui.client;

import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.common.AuthenticationException;
import org.wso2.carbon.identity.authenticator.oauth2.sso.stub.OAUTH2SSOAuthenticationServiceStub;
import org.wso2.carbon.identity.authenticator.oauth2.sso.stub.types.AuthnReqDTO;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.ServerConstants;

import javax.servlet.http.HttpSession;
import java.rmi.RemoteException;
import java.util.UUID;

public class OAUTH2SSOAuthenticationClient {
    private  OAUTH2SSOAuthenticationClient(){

    }

    private static final Log log = LogFactory.getLog(OAUTH2SSOAuthenticationClient.class);
    private OAUTH2SSOAuthenticationServiceStub stub;
    private HttpSession session;

    public OAUTH2SSOAuthenticationClient(ConfigurationContext ctx, String serverURL, String cookie,
                                        HttpSession session) throws Exception {
        this.session = session;
        String serviceEPR = serverURL + "OAUTH2SSOAuthenticationService";
        stub = new OAUTH2SSOAuthenticationServiceStub(ctx, serviceEPR);
        ServiceClient client = stub._getServiceClient();
        Options options = client.getOptions();
        options.setManageSession(true);
        if (cookie != null) {
            options.setProperty(HTTPConstants.COOKIE_STRING, cookie);
        }
    }

    public boolean login(String tenant, String username) throws AuthenticationException {
        try {
            AuthnReqDTO authDTO = new AuthnReqDTO();
            authDTO.setResponse(username);
            authDTO.setTenant(tenant);
            boolean authStatus = stub.login(authDTO);
            setAdminCookie(authStatus);
            //Add an entry to the CarbonSSOSessionManager
            return authStatus;
        } catch (RemoteException e) {
            log.error("Error when sign-in for the user : " + username, e);
            throw new AuthenticationException("Error when sign-in for the user : " + username, e);
        }
    }

    public void logout(HttpSession session) throws AuthenticationException {
        try {
            if (!CarbonUtils.isRunningOnLocalTransportMode()) {
                stub.logout();
            }
            session.removeAttribute(ServerConstants.ADMIN_SERVICE_AUTH_TOKEN);
        } catch (java.lang.Exception e) {
            String msg = "Error occurred while logging out";
            log.error(msg, e);
            throw new AuthenticationException(msg, e);
        }
    }

    private void setAdminCookie(boolean result) {
        if (result) {
            String cookie = (String) stub._getServiceClient().getServiceContext().getProperty(
                    HTTPConstants.COOKIE_STRING);
            if (cookie == null) {
                // For local transport - the cookie will be null.
                // This generated cookie cannot be used for any form authentication with the backend.
                // This is done to be backward compatible.
                cookie = UUID.randomUUID().toString();
            }
            session.setAttribute(ServerConstants.ADMIN_SERVICE_AUTH_TOKEN, cookie);
        }
    }

}
