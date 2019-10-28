function checkAll(formname, checktoggle) {
  checkboxes = document[formname].getElementsByTagName('input');
  for (var i=0; i<checkboxes.length; i++)  {
    if (checkboxes[i].name != "multiselect" && checkboxes[i].name.search("security_settings_options") <= 0) {
        if (checkboxes[i].type == 'checkbox' && checkboxes[i].checked == false ) {
            checkboxes[i].checked = checktoggle;
        } else {
            checkboxes[i].checked = false;
        }
    }
  }
}
function uncheck() {
    document.getElementById("pareto_security_settings_options[hard_ban_mode]").checked = false;
    document.getElementById("pareto_security_settings_options[tor_block]").checked = false;
}
function checkRow(chkrow, thisrow) {
    if (typeof(chkrow) == "object") {
        if (document.getElementById(thisrow).checked === false ) {
            document.getElementById(thisrow).checked = true;
        } else {
            document.getElementById(thisrow).checked = false;
        }
    } else {
        return false;
    }
}
