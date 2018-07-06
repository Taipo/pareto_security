function check() {
    document.getElementById("pareto_security_settings_options[hard_ban_mode]").checked = true;
}
function uncheck() {
    document.getElementById("pareto_security_settings_options[hard_ban_mode]").checked = false;
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
