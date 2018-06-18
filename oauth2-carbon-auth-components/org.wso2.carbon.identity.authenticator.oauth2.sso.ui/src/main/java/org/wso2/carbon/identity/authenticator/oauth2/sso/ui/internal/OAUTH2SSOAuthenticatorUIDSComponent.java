package org.wso2.carbon.identity.authenticator.oauth2.sso.ui.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.authenticator.OAUTH2SSOUIAuthenticator;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.filters.LoginPageFilter;
import org.wso2.carbon.identity.authenticator.oauth2.sso.ui.filters.LogoutFilter;
import org.wso2.carbon.identity.authenticator.oauth2.sso.common.Util;

import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.ui.CarbonSSOSessionManager;
import org.wso2.carbon.ui.CarbonUIAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

import javax.servlet.Filter;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Dictionary;
import java.util.Hashtable;

/**
 * @scr.component name="oauth2.sso.authenticator.ui.dscomponent" immediate="true"
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService"
 * cardinality="1..1" policy="dynamic" bind="setRegistryService"
 * unbind="unsetRegistryService"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService"
 * unbind="unsetRealmService"
 * @scr.reference name="config.context.service"
 * interface="org.wso2.carbon.utils.ConfigurationContextService"
 * cardinality="1..1" policy="dynamic"
 * bind="setConfigurationContextService"
 * unbind="unsetConfigurationContextService"
 * @scr.reference name="org.wso2.carbon.ui.CarbonSSOSessionManager"
 * interface="org.wso2.carbon.ui.CarbonSSOSessionManager"
 * cardinality="1..1" policy="dynamic"
 * bind="setCarbonSSOSessionManagerInstance"
 * unbind="unsetCarbonSSOSessionManagerInstance"
 */

public class OAUTH2SSOAuthenticatorUIDSComponent {

    private static final Log log = LogFactory.getLog(OAUTH2SSOAuthenticatorUIDSComponent.class);

    protected void activate(ComponentContext ctxt) {
        try {
            if (Util.isAuthenticatorEnabled()) {
                // initialize the SSO Config params during the start-up
                boolean initSuccess = Util.initSSOConfigParams();
                
                if (initSuccess) {
                    HttpServlet loginServlet = new HttpServlet() {
                        @Override
                        protected void doPost(HttpServletRequest req, HttpServletResponse resp)
                                throws ServletException, IOException {
                            throw new UnsupportedOperationException();

                        }
                    };
                    // register a servlet filter for SSO redirector page
                    HttpServlet logoutServlet = new HttpServlet() {
                    	protected void doGet(HttpServletRequest request, HttpServletResponse response)
                                throws ServletException, IOException {
                        }
                    };

                    Filter loginPageFilter = new LoginPageFilter();
                    Dictionary loginPageFilterProps = new Hashtable(2);
                    Dictionary redirectorParams = new Hashtable(3);

                    redirectorParams.put("url-pattern", Util.getLoginPage()); 

                    redirectorParams.put("associated-filter", loginPageFilter);
                    redirectorParams.put("servlet-attributes", loginPageFilterProps);
                    ctxt.getBundleContext().registerService(Servlet.class.getName(),
                            loginServlet, redirectorParams);
                    
                    Filter logoutPageFilter = new LogoutFilter();
                    Dictionary logoutPageFilterProps = new Hashtable(2);
                    Dictionary redirectorParamslogut = new Hashtable(3);

                    redirectorParamslogut.put("url-pattern", "/carbon/stratos-auth/redirect_ajaxprocessor.jsp"); 

                    redirectorParamslogut.put("associated-filter", logoutPageFilter);
                    redirectorParamslogut.put("servlet-attributes", logoutPageFilterProps);
                    ctxt.getBundleContext().registerService(Servlet.class.getName(),
                    		logoutServlet, redirectorParamslogut);
                    
                    // register the UI authenticator
                    OAUTH2SSOUIAuthenticator authenticator = new OAUTH2SSOUIAuthenticator();
                    Hashtable<String, String> props = new Hashtable<String, String>();
                    props.put(CarbonConstants.AUTHENTICATOR_TYPE, authenticator.getAuthenticatorName());
                    ctxt.getBundleContext().registerService(CarbonUIAuthenticator.class.getName(),
                            authenticator, props);
                    log.debug("OAUTH2 SSO Authenticator BE Bundle activated successfully.");
                } else {
                    log.warn("Initialization failed for SSO Authenticator. Starting with the default authenticator");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("OAUTH2 SSO Authenticator is disabled");
                }
            }
        } catch (Throwable e) {
            log.error("OAUTH2 Authentication Failed");
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        log.debug("AAC SSO Authenticator FE Bundle is deactivated ");
    }

    protected void setRegistryService(RegistryService registryService) {
        OAUTH2SSOAuthFEDataHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {
        OAUTH2SSOAuthFEDataHolder.getInstance().setRegistryService(null);
    }

    protected void setRealmService(RealmService realmService) {
        OAUTH2SSOAuthFEDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        OAUTH2SSOAuthFEDataHolder.getInstance().setRealmService(null);
    }

    protected void setConfigurationContextService(ConfigurationContextService configCtxtService) {
        OAUTH2SSOAuthFEDataHolder.getInstance().setConfigurationContextService(configCtxtService);
    }

    protected void unsetConfigurationContextService(ConfigurationContextService configCtxtService) {
        OAUTH2SSOAuthFEDataHolder.getInstance().setConfigurationContextService(null);
    }

    protected void setCarbonSSOSessionManagerInstance(CarbonSSOSessionManager carbonSSOSessionMgr) {
        OAUTH2SSOAuthFEDataHolder.getInstance().setCarbonSSOSessionManager(carbonSSOSessionMgr);
    }

    protected void unsetCarbonSSOSessionManagerInstance(CarbonSSOSessionManager carbonSSOSessionMgr) {
        OAUTH2SSOAuthFEDataHolder.getInstance().setCarbonSSOSessionManager(null);
    }
}
