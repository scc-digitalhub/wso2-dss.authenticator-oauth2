<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar"
           prefix="carbon" %>
<jsp:include page="../dialog/display_messages.jsp"/>

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
                <li><p><fmt:message key='auth.failure.reason.1'/></p></li>
                <li><p><fmt:message key='auth.failure.reason.2'/></p></li>
                <li><p><fmt:message key='auth.failure.reason.3'/></p></li>
            </ul>
            <div class="authFailuresTryAgain">Please <a href="../admin/logout_action.jsp">Try Again.</a></div>
        </div>
    </div>
</fmt:bundle>