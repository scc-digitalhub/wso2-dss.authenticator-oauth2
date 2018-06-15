<%@ page
        import="org.wso2.carbon.identity.authenticator.oauth2.sso.common.OAUTH2SSOAuthenticatorConstants" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar"
           prefix="carbon" %>
<jsp:include page="../dialog/display_messages.jsp"/>
<%
String statusMessage = request.getParameter("error");
session.invalidate();
%>
<style>
.info-box{
background-color:#EEF3F6;
border:1px solid #ABA7A7;
font-size:13px;
font-weight:bold;
margin-bottom:10px;
padding:10px;
}
</style>
<link href="css/authFailures.css" type="text/css" rel="stylesheet" />
<fmt:bundle basename="org.wso2.carbon.identity.authenticator.oauth2.sso.ui.i18n.Resources">
    <div id="middle">
        <div id="workArea">
            <p></p>

            <div class="authFailuresMsg">
                <h2><fmt:message key='auth.failure'/></h2>
                <p><fmt:message key='auth.failure.reason'/></p>
            </div>

            <ul class="authFailures">
                <li><p><fmt:message key='<%= statusMessage %>'/></p></li>
            </ul>
            <div class="authFailuresTryAgain">Please <a href="../admin/logout_action.jsp">Try Again.</a></div>
        </div>
    </div>
</fmt:bundle>