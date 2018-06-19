package org.wso2.carbon.identity.authenticator.oauth2.sso.dto;
/*
 * Data Transfer Object between OAuth Provider and WSO2 Carbon
 */

public class AuthnReqDTO {

    private String response;
    private String tenant;
    private boolean isAdmin;

    public String getResponse() {
        return response;
    }

    public void setResponse(String response) {
        this.response = response;
    }
    
    public String getTenant() {
        return tenant;
    }

    public void setTenant(String tenant) {
        this.tenant = tenant;
    }
    
    public boolean getIsAdmin() {
        return isAdmin;
    }

    public void setIsAdmin(boolean isAdmin) {
        this.isAdmin = isAdmin;
    }

}
