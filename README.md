# OAuth2 Custom Authenticator for WSO2 Carbon

This component provides a set of bundles for the purpose of enabling OAUTH2 authentication in WSO2 Carbon.

# Table of contents

  * [1. Running](#1-running)
  * [2. Configuring OAuth2 providers](#2-configuring-oauth2-providers)
    * [2.1 Google OAuth2 provider configurations](#21-google-oauth2-provider-configurations)
      * [2.1.1 Google Developer Console Config](#211-google-developer-console-config)
      * [2.1.2 DSS Config](#212-dss-config)
    * [2.2 AAC OAuth2 provider configurations](#22-aac-oauth2-provider-configurations)
      * [2.2.1 AAC Developer Console Config](#221-aac-developer-console-config)
      * [2.2.2 DSS Config](#222-dss-config)
  
# 1. Running

Execute the following command in order to generate the necessary jars and put each of them inside the folder $WSO2_DIR/repository/components/dropins

```bash
mvn clean install

```
This component is being integrated inside the enhanced version of product-dss. You can find [`here`](https://github.com/coinnovationlab/product-dss) instructions on how to deploy it.
# 2. Configuring OAuth2 providers


## 2.1 Google OAuth2 provider configurations

### 2.1.1 Google Developer Console Config
- Go to the Google Developers Console by accessing [`this link`](https://console.developers.google.com/).
- Select a project, or create a new one by clicking Create Project.
- In the Project name field, type in a name for your project (i.e WSO2).
- In the Project ID field, optionally type in a project ID for your project or use the one that the console has created for you.
- Click the Create button and wait for the project to be created.
- Click on the new project name in the list to start editing the project.
- In the sidebar under “APIs & Services”, select Credentials.
- Click Create a new Client ID — a dialog box appears.
- In the Application type section of the dialog, select Web application.
- Wildcards are not allowed. In the example below, the second URL could be a production URL.
	http://localhost:8080
	https://myproductionurl.example.com
- In the “Authorized redirect URIs” put this URL:
	http://your_host/your_wso2/carbon/oauth2_acs
- Click the Create Client ID button.
- After completion, you will get a client id and client secret id.

### 2.1.2 DSS Config 

In the file repository/conf/security/authenticators.xml put the following xml configuration
```bash
    <!-- Example Google OAUTH2 provider -->
    <Authenticator name="OAUTH2SSOAuthenticator" disabled="false">
	  <Priority>3</Priority>
	  <Config>
	     <Parameter name="OauthProviderName">Google</Parameter>
	     <Parameter name="LoginPage">/carbon/admin/login.jsp</Parameter>
             <Parameter name="ServiceProviderID">carbonServer</Parameter>
	     <Parameter name="LandingPage">https://localhost:9444/carbon/oauth2-sso-acs/custom_login.jsp</Parameter>
	     <Parameter name="RedirectURL">https://localhost:9444/oauth2_acs</Parameter>
	     <Parameter name="UserProvisioningEnabled">true</Parameter>
	     <Parameter name="TenantProvisioningEnabled">true</Parameter>
	     <Parameter name="TenantDefault">testdomain.com</Parameter>
	     <Parameter name="ClientID">YOUR_GOOGLE_CLIENT_ID</Parameter>
	     <Parameter name="ClientSecret">YOUR_GOOGLE_CLIENT_SECRET</Parameter>
  	     <Parameter name="AuthorizationURL">https://accounts.google.com/o/oauth2/auth</Parameter>
	     <Parameter name="TokenURL">https://accounts.google.com/o/oauth2/token</Parameter>
	     <Parameter name="CheckTokenEndpointUrl">https://www.googleapis.com/oauth2/v1/tokeninfo</Parameter>
	     <Parameter name="APIUserInfoURL">https://www.googleapis.com/oauth2/v1/userinfo</Parameter>
	     <Parameter name="ScopesListUserInfo">email profile</Parameter>
	     <Parameter name="UserNameField">email</Parameter>
	  </Config>
    </Authenticator>
```

## 2.2 AAC OAuth2 provider configurations

### 2.2.1 AAC Developer Console Config

For information on how to generate AAC ClientID and ClientSecret refer to the [`AAC Repository`](https://github.com/smartcommunitylab/AAC).

### 2.2.2 DSS Config

In the file repository/conf/security/authenticators.xml put the following xml configuration
```bash
    <!-- Example AAC OAUTH2 provider -->
    <Authenticator name="OAUTH2SSOAuthenticator" disabled="false">
  <Priority>3</Priority>
  <Config>
     <Parameter name="OauthProviderName">AAC</Parameter>
     <Parameter name="LoginPage">/carbon/admin/login.jsp</Parameter>
     <Parameter name="ServiceProviderID">carbonServer</Parameter>
     <Parameter name="IdentityProviderSSOServiceURL">http://localhost:8080/aac</Parameter>
     <Parameter name="LandingPage">https://mydomain.com/dss_proxy_context_path/carbon/oauth2-sso-acs/custom_login.jsp</Parameter>
     <Parameter name="RedirectURL">https://mydomain.com/dss_proxy_context_path/oauth2_acs</Parameter>
     <Parameter name="UserProvisioningEnabled">true</Parameter>
     <Parameter name="TenantProvisioningEnabled">true</Parameter>
     <Parameter name="TenantDefault">testdomain.com</Parameter>
     <Parameter name="ClientID">YOUR_AAC_CLIENT_ID</Parameter>
     <Parameter name="ClientSecret">YOUR_AAC_CLIENT_SECRET</Parameter>
     <Parameter name="AuthorizationURL">http://localhost:8080/aac/oauth/authorize</Parameter>
     <Parameter name="TokenURL">http://localhost:8080/aac/oauth/token</Parameter>
     <Parameter name="CheckTokenEndpointUrl">http://localhost:8080/aac/resources/token</Parameter>
     <Parameter name="APIUserInfoURL">http://localhost:8080/aac/basicprofile/me</Parameter>
     <Parameter name="APIRoleInfoURL">http://localhost:8080/aac/userroles/me</Parameter>
     <Parameter name="GetRolesOfTokenURL">http://localhost:8080/aac/userroles/token</Parameter>
     <Parameter name="ApiKeyCheckURL">http://localhost:8080/aac/apikeycheck</Parameter>
     <Parameter name="MaxExpireSecToken">86400</Parameter>	     
     <Parameter name="ScopesListUserInfo">profile.basicprofile.me profile.accountprofile.me user.roles.me user.roles.read</Parameter>
     <Parameter name="UserNameField">username</Parameter>
     <Parameter name="RoleContext">YOUR_ROLE_CONTEXT</Parameter>
     <Parameter name="SelectTenantURL">https://mydomain.com/dss_proxy_context_path/carbon/oauth2-sso-acs/select_tenant.jsp</Parameter>
     <Parameter name="TenantSelectedURL">https://mydomain.com/dss_proxy_context_path/forwardtenant</Parameter>
     <Parameter name="OauthProviderName">AAC</Parameter>
     <Parameter name="SecurityFilterClass">org.wso2.carbon.dataservices.core.security.filter.ServicesSecurityFilter</Parameter>
  </Config>
</Authenticator>
```

Edit the file `repository/conf/tomcat/web.xml` by adding the cookie-config tag:
```bash
	<session-config>
		<session-timeout>30</session-timeout>
		<cookie-config>
		         <name>JSESSIONID_DSS</name>
		</cookie-config>
	</session-config>
```




