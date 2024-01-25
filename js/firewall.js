var format_firewall_global_state = function(colNumber, row){
    var col = $('td:eq('+colNumber+')', row),
        colvar = col.text();
    if (colvar == "0"){
        colvar = '<span class="label label-danger">'+i18n.t('firewall.allow_all')+'</span>'
    } else if (colvar == "1"){
        colvar = '<span class="label label-warning">'+i18n.t('firewall.limit')+'</span>'
    } else if (colvar == "2"){
        colvar = '<span class="label label-success">'+i18n.t('firewall.block_all')+'</span>'
    } else {
        colvar = colvar
    }
    col.html(colvar)
}