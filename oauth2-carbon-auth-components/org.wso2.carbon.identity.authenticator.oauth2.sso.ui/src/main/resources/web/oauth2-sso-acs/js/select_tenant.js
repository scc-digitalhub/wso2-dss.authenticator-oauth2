$("input[type=radio]").change(function() {
	$("#proceedButton").prop("disabled", false);
});

function setRole(roleName){
	document.getElementsByName("selectedRole").item(0).value = roleName;
}