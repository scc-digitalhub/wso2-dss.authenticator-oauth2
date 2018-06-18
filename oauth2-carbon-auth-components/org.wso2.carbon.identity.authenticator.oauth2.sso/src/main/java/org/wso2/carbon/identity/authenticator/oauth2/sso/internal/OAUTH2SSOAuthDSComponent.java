package org.wso2.carbon.identity.authenticator.oauth2.sso.internal;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.core.security.AuthenticatorsConfiguration;
import org.wso2.carbon.core.services.authentication.CarbonServerAuthenticator;
import org.wso2.carbon.identity.authenticator.oauth2.sso.OAUTH2SSOAuthenticator;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Hashtable;
import java.util.Map;

/**
 * @scr.component name="oauth2.sso.authenticator.dscomponent" immediate="true"
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService"
 * cardinality="1..1" policy="dynamic" bind="setRegistryService"
 * unbind="unsetRegistryService"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService"
 * unbind="unsetRealmService"
 */
public class OAUTH2SSOAuthDSComponent {

    private static final Log log = LogFactory.getLog(OAUTH2SSOAuthDSComponent.class);

    protected void activate(ComponentContext ctxt) {
        try {
        	log.debug("OAUTH2 SSO Authenticator BE Bundle started .");
            OAUTH2SSOAuthBEDataHolder.getInstance().setBundleContext(ctxt.getBundleContext());
            OAUTH2SSOAuthenticator authenticator = new OAUTH2SSOAuthenticator();
            Hashtable<String, String> props = new Hashtable<String, String>();
            props.put(CarbonConstants.AUTHENTICATOR_TYPE, authenticator.getAuthenticatorName());
            ctxt.getBundleContext().registerService(CarbonServerAuthenticator.class.getName(), authenticator, props);

            if (log.isDebugEnabled()) {
                log.debug("OAUTH2 SSO Authenticator BE Bundle activated successfuly.");
            }
        } catch (Throwable e) {
            if (log.isDebugEnabled()) {
                log.error("OAUTH2 SSO Authenticator BE Bundle activation Failed.");
            }
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        OAUTH2SSOAuthBEDataHolder.getInstance().setBundleContext(null);
        log.debug("OAUTH2 SSO Authenticator BE Bundle is deactivated ");
    }

    protected void setRegistryService(RegistryService registryService) {
        OAUTH2SSOAuthBEDataHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {
        OAUTH2SSOAuthBEDataHolder.getInstance().setRegistryService(null);
    }

    protected void setRealmService(RealmService realmService) {
        OAUTH2SSOAuthBEDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        OAUTH2SSOAuthBEDataHolder.getInstance().setRealmService(null);
    }
}
