package org.wso2.carbon.identity.authenticator.oauth2.sso.common;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class AuthorizationToken {

	private String access_token;
	private String token_type;
	private int expires_in;
    private String refresh_token ;
    private String id_token;
    private String scope;
    private String jti;
    
    public AuthorizationToken() {
    	
    }
        
    public AuthorizationToken( String access_token, String token_type, int expires_in, String refresh_token, String id_token, String scope) {
    	
    	this.access_token = access_token;
		this.token_type = token_type;
		this.expires_in = expires_in;
		this.refresh_token = refresh_token;
		this.id_token = id_token;
		this.scope = scope;
    }

	public String getId_token() {
    	return id_token;
    }
    
    public void setId_token(String id_token) {
    	this.id_token = id_token;
    }
    
    public String getAccess_token() {
    	return access_token;
    }
    
    public void setAccess_token(String httpCode) {
    	this.access_token = httpCode;
    }
        
    public String getToken_type() {
    	return token_type;
    }
    
    public void setToken_type(String token_type) {
    	this.token_type = token_type;
    }
    
    public int getExpires_in() {
    	return expires_in;
    }
    
    public void setExpires_in(int expires_in) {
    	this.expires_in = expires_in;
    }
    
    public String getRefresh_token() {
    	return refresh_token;
    }
    
    public void setRefresh_token(String refresh_token) {
    	this.refresh_token = refresh_token;
    }
    
    public String getScope() {
    	return scope;
    }
    
    public void setScope(String scope) {
    	this.scope = scope;
    }

	public String getJti() {
		return jti;
	}

	public void setJti(String jti) {
		this.jti = jti;
	}
    
}
