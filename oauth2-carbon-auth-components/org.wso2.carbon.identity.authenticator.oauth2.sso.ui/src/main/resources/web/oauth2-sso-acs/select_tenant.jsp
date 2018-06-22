<%@ page contentType="text/html;charset=UTF-8" language="java" pageEncoding="UTF-8"%>
<%@ page import="java.util.List"%>
<%@ page import="org.wso2.carbon.identity.authenticator.oauth2.sso.common.AACRole"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<link href="css/select_tenant.css" type="text/css" rel="stylesheet" />

<div id="tenantsSelection">
	<span class="tenantsTitle">Select Tenant<br></span>${tenantSelectedURL}
	<form id="tenantsForm" action="${tenantSelectedURL}" method="post">
		<c:if test="${tenantList == null || tenantList.size() == 0}">
			<span class="tenantsImportant">Error</span>: no tenants found.
		</c:if>
		<c:if test="${tenantList != null && tenantList.size() >= 1}">
			<span class="tenantsImportant">Multiple tenants available</span> for this user. Please select the one you wish to sign in with.<br>
			<c:forEach items="${tenantList}" var="tenant">
				<input class="tenantsElement" type="radio" name="tenantRadio" value="${tenant.getRole()}">${tenant.getRole()}<br>
			</c:forEach>
			<button type="submit" id="proceedButton">Proceed</button>
		</c:if>
	</form>
</div>