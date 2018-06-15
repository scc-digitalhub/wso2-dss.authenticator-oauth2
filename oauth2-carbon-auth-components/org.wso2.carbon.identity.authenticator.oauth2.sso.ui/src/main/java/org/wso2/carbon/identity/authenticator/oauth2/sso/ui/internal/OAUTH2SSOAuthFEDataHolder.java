package org.wso2.carbon.identity.authenticator.oauth2.sso.ui.internal;

import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.ui.CarbonSSOSessionManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

/**
 * This class is used as the Singleton data holder for AAC SSO Authentication FE module.
 */
public class OAUTH2SSOAuthFEDataHolder {
    private static OAUTH2SSOAuthFEDataHolder instance = new OAUTH2SSOAuthFEDataHolder();

    private RealmService realmService;
    private RegistryService registryService;
    private ConfigurationContextService configurationContextService;
    private CarbonSSOSessionManager carbonSSOSessionManager;

    private OAUTH2SSOAuthFEDataHolder() {
    }

    public static OAUTH2SSOAuthFEDataHolder getInstance() {
        return instance;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    public RegistryService getRegistryService() {
        return registryService;
    }

    public void setRegistryService(RegistryService registryService) {
        this.registryService = registryService;
    }

    public ConfigurationContextService getConfigurationContextService() {
        return configurationContextService;
    }

    public void setConfigurationContextService(
            ConfigurationContextService configurationContextService) {
        this.configurationContextService = configurationContextService;
    }

    public CarbonSSOSessionManager getCarbonSSOSessionManager() {
        return carbonSSOSessionManager;
    }

    public void setCarbonSSOSessionManager(CarbonSSOSessionManager carbonSSOSessionManager) {
        this.carbonSSOSessionManager = carbonSSOSessionManager;
    }
}
