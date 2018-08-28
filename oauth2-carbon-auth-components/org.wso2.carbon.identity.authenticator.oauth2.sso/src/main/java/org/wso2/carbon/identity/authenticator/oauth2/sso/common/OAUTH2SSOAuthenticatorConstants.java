package org.wso2.carbon.identity.authenticator.oauth2.sso.common;

public final class OAUTH2SSOAuthenticatorConstants {
    private OAUTH2SSOAuthenticatorConstants(){

    }
    public static final String AUTHENTICATOR_NAME = "OAUTH2SSOAuthenticator";

    public static final String OAUTH2_NAME_ID_POLICY_TRANSIENT = "urn:oasis:names:tc:OAUTH2:2.0:nameid-format:transient";
    public static final String OAUTH2_NAME_ID_POLICY_UNSPECIFIED = "urn:oasis:names:tc:OAUTH2:1.1:nameid-format:unspecified";

    public static final String OAUTH2_NAME_ID_POLICY_PERSISTENT = "urn:oasis:names:tc:OAUTH2:2.0:nameid-format:persistent";
    public static final String OAUTH2_NAME_ID_POLICY_EMAIL = "urn:oasis:names:tc:OAUTH2:1.1:nameid-format:emailAddress";
    public static final String OAUTH2_NAME_ID_POLICY_ENTITY = "urn:oasis:names:tc:OAUTH2:2.0:nameid-format:entity";

    public static final String NAMEID_POLICY_FORMAT = "NameIDPolicyFormat";
    public static final String LOGOUT_USER = "urn:oasis:names:tc:OAUTH2:2.0:logout:user";

    public static final String HTTP_POST_PARAM_RELAY_STATE = "RelayState";
    public static final String HTTP_ATTR_OAUTH2_RESP_TOKEN = "access_token";
    public static final String HTTP_ATTR_OAUTH2_RESP_AUTH_CODE = "code";
    public static final String OAUTH2_AUTH_CODE_STATE = "state";
    public static final String HTTP_ATTR_IS_LOGOUT_REQ = "logoutRequest";

    public static final String NOTIFICATIONS_ERROR_CODE = "ErrorCode";
    public static final String NOTIFICATIONS_ERROR_MSG = "ErrorMessage";
    public static final String LOG_OUT_REQ = "logout";
    public static final String LOGGED_IN_USER = "loggedInUser";
    public static final String HTTP_POST_PARAM_OAUTH2_ROLES = "Roles";
    public static final String IS_ADMIN = "isAdmin";

    public static final String IDP_SESSION_INDEX = "idpSessionIndex";

    // SSO Configuration Params
    public static final String SERVICE_PROVIDER_ID = "ServiceProviderID";
    public static final String IDENTITY_PROVIDER_SSO_SERVICE_URL = "IdentityProviderSSOServiceURL";
    public static final String LOGIN_PAGE = "LoginPage";
    public static final String LANDING_PAGE = "LandingPage";
    public static final String EXTERNAL_LOGOUT_PAGE = "ExternalLogoutPage";
    public static final String LOGOUT_SUPPORTED_IDP = "LogoutSupportedIDP";
    public static final String ASSERTION_CONSUMER_SERVICE_URL = "AssertionConsumerServiceURL";
    public static final String ASSERTION_CONSUMER_URL = "AssertionConsumerServiceURL";
    public static final String FEDERATION_CONFIG = "FederationConfig";
    public static final String FEDERATION_CONFIG_USER = "FederationConfigUser";
    public static final String FEDERATION_CONFIG_PASSWORD = "FederationConfigPassword";
    public static final String LOGIN_ATTRIBUTE_NAME = "LoginAttributeName";
    public static final String IDENTITY_PROVIDER_SLO_SERVICE_URL = "IdentityProviderSLOServiceURL";
    public static final String AUDIT_MESSAGE = "Initiator : %s | Action : %s | Target : %s | Data : { %s } | Result : %s ";
    public static final String AUDIT_ACTION_LOGIN = "Login";
    public static final String AUDIT_ACTION_LOGOUT = "Logout";
    public static final String AUDIT_RESULT_SUCCESS = "Success";
    public static final String AUDIT_RESULT_FAILED = "Failed";
    public static final String AUTH_CONFIG_PARAM_IDP_CERT_ALIAS = "IdPCertAlias";
    public static final String RESPONSE_SIGNATURE_VALIDATION_ENABLED = "ResponseSignatureValidationEnabled";
    public static final String ASSERTION_SIGNATURE_VALIDATION_ENABLED = "AssertionSignatureValidationEnabled";
    public static final String VALIDATE_SIGNATURE_WITH_USER_DOMAIN = "VerifySignatureWithUserDomain";
    public static final String TIME_STAMP_SKEW = "TimestampSkew";
    public static final String ROLE_CLAIM_ATTRIBUTE = "RoleClaimAttribute";
    public static final String ATTRIBUTE_VALUE_SEPARATOR = "AttributeValueSeparator";

    public static final String JIT_USER_PROVISIONING_ENABLED = "UserProvisioningEnabled";
    public static final String TENANT_PROVISIONING_ENABLED = "TenantProvisioningEnabled";
    public static final String PROVISIONING_DEFAULT_USERSTORE = "ProvisioningDefaultUserstore";
    public static final String PROVISIONING_DEFAULT_ROLE = "ProvisioningDefaultRole";
    public static final String IS_SUPER_ADMIN_ROLE_REQUIRED = "IsSuperAdminRoleRequired";
    
    //OAUTH2 parameters
    public static final String CLIENT_ID = "ClientID";
    public static final String CLIENT_SECRET = "ClientSecret";	     
    public static final String REDIRECT_URL = "RedirectURL";
    public static final String LOGOUT_URL = "LogoutURL";
    public static final String AUTHORIZATION_URL = "AuthorizationURL";
    public static final String TOKEN_URL = "TokenURL";
    public static final String CHECK_TOKEN_ENDPOINT_URL = "CheckTokenEndpointUrl";
    public static final String ROLES_OF_TOKEN_URL = "GetRolesOfTokenURL";
    public static final String APIKEY_CHECK_URL = "ApiKeyCheckURL";
    public static final String API_USER_INFO_URL = "APIUserInfoURL";
    public static final String API_ROLE_INFO_URL = "APIRoleInfoURL";
    public static final String MAX_EXPIRE_SEC_TOKEN = "MaxExpireSecToken";
    public static final String MAX_EXPIRE_SEC_TOKEN_VALUE= "86400";
    public static final String SCOPES_LIST_USER_INFO = "ScopesListUserInfo";
    public static final String SCOPES_LIST_ROLE_INFO = "ScopesListRoleInfo";
    public static final String USER_NAME_FIELD = "UserNameField";
    public static final String TENANT_DEFAULT = "TenantDefault";
    public static final String SELECT_TENANT_URL = "SelectTenantURL";
    public static final String TENANT_SELECTED_URL = "TenantSelectedURL";
    public static final String OAUTH_PROVIDER_NAME = "OauthProviderName";
    
    
    //AAC parameters
    public static final String ROLE_SPACE = "RoleSpace";
    public static final String ROLE_CONTEXT= "RoleContext";
    public static final String ROLE_SPACE_VALUE = "dss.com"; 
    public static final String ROLE_CONTEXT_VALUE = "components/dss.super";
    public static final String ROLE_PROVIDER = "ROLE_PROVIDER";

    public static final class ErrorMessageConstants {
        private ErrorMessageConstants(){

        }
        public static final String RESPONSE_NOT_PRESENT = "response.not.present";
        public static final String RESPONSE_INVALID = "response.invalid";
        public static final String RESPONSE_MALFORMED = "response.malformed";
        public static final String RESPONSE_TOKEN_ERROR = "response.token.error";
        public static final String SUCCESSFUL_SIGN_OUT = "successful.signed.out";
        public static final String RESPONSE_USER_ERROR= "response.user.profile.error";
        public static final String RESPONSE_ROLES_LIST_ERROR= "response.role.list.error";
        public static final String RESPONSE_ROLE_MISSING_ERROR= "response.role.missing.error";
        public static final String RESPONSE_NO_DOMAIN_CREATED_BY_PROVIDER_ERROR= "response.domain.notcreated";
        public static final String RESPONSE_NO_DOMAIN_ACTIVE_BY_PROVIDER_ERROR= "response.domain.notactivated";
    }
}
