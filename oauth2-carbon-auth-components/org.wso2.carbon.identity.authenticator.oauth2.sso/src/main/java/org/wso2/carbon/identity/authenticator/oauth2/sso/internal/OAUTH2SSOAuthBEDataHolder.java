package org.wso2.carbon.identity.authenticator.oauth2.sso.internal;

import org.osgi.framework.BundleContext;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

public class OAUTH2SSOAuthBEDataHolder {

	private static OAUTH2SSOAuthBEDataHolder instance = new OAUTH2SSOAuthBEDataHolder();

    private RegistryService registryService;
    private RealmService realmService;
    private BundleContext bundleContext;

    private OAUTH2SSOAuthBEDataHolder() {
    }

    public static OAUTH2SSOAuthBEDataHolder getInstance() {
        return instance;
    }

    public RegistryService getRegistryService() {
        return registryService;
    }

    public void setRegistryService(RegistryService registryService) {
        this.registryService = registryService;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    public BundleContext getBundleContext() {
        return bundleContext;
    }

    public void setBundleContext(BundleContext bundleContext) {
        this.bundleContext = bundleContext;
    }
}
