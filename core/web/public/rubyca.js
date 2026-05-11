jQuery( document ).ready(function( $ ) {
  /*
  Generic bootstrap 5 modal dialog to get plain text using ajax
  */
 
  $.fn.infomodal = function(title) {
    if(title===undefined || title===null ){
      title= "Info"
    }

    $("body").append(
      $("<div/>", { id: "infomodal", class: "modal fade bd-example-modal-lg", role: "dialog", tabindex: "-1", "aria-labelledby": "Info"}).append(
        $("<div/>", {class: "modal-dialog modal-lg", role: "document"}).append(
          $("<div/>", {class: "modal-content"}).append(
            // Header
            $("<div/>", {class: "modal-header"}).append(
              $("<h3/>").text(title),
              $("<button/>", { type: "button", class: "btn-close", "data-bs-dismiss": "modal", "aria-label": "Close" })
            ),
            // Body
            $("<div/>", {class: "modal-body"}).append(this),
            //Footer
            $("<div/>", {class: "modal-footer"}).html('<button type="button" class="btn btn-primary" data-bs-dismiss="modal">Close</button>')
          )
        )
      )
    );

    $('#infomodal').on('hide.bs.modal', function () {
      document.activeElement.blur();
    });

    $('#infomodal').on('hidden.bs.modal', function (){
      $('#infomodal').remove();
    });

    var infoModal = new bootstrap.Modal(document.getElementById("infomodal"), {});
    infoModal.show();
  };
  
  $('a#download').click(function(){
    setTimeout(function() {
      window.location.replace("/admin/certificates");
      }, 700);
  });

  // trigger to create modal
  $('[data-bs-get="modal"]').click( function(e) {
    e.preventDefault();
    
    var modal_title = null;
    if ($(this).is('[data-bs-title]')) { 
      modal_title = $(this).attr('data-bs-title')
    };
		$.ajax({    
      url: $(this).attr("href"), 
      success: function(data) {
        $('<pre/>').text(data).infomodal(modal_title);
      },    
      error: function(jqXHR, textStatus, errorThrown) { 
        $('<p/>').html("Woops. Error on get info.<br/><br/>"+ jqXHR.status + " " + errorThrown).infomodal("Error");
      }
    });
  });
  
  // BS Tooltip
  $('[data-bs-toggle="tooltip"]').tooltip();
  $('[data-bs-toggle="tooltip"]').on('shown.bs.tooltip', function(e) {
    setTimeout(function () {
      $(e.target).tooltip('hide'); 
    }, 5000);
  });

  //Show and hide password input
  $('.input-group-text.show-pass').click( function(e) {
    const pw_input = $(this).parent().parent().find('input.form-control');
    const bt_show_icon = $(this).find('i');
    pw_input.focus();

    if (pw_input.attr('type') === 'password'){
      pw_input.attr('type','text');
      
      bt_show_icon.removeClass('fa-eye');
      bt_show_icon.addClass('fa-eye-slash');
      
      bt_show_icon.parent().tooltip('hide')
                  .attr('data-bs-original-title', 'Hide password')
                  .tooltip('show');
      

      //bt_show_icon.parent().tooltip('dispose').tooltip({title: 'Hide password'}).tooltip('show');                  

      pw_input.one('blur', function(e) {
        if ($(this).attr('type') === 'text' && (e.relatedTarget !== undefined && e.relatedTarget  !== null)){
          $(this).attr('type', 'password')
          bt_show_icon.removeClass('fa-eye-slash');
          bt_show_icon.addClass('fa-eye');
          
          bt_show_icon.parent().tooltip('hide')
                      .attr('data-bs-original-title', 'Show password')
                      .tooltip('show');
          
          //bt_show_icon.parent().tooltip('dispose').tooltip({title: 'Show password'}).tooltip('show'); 
        }
      });
    }
    else{
      pw_input.attr('type','password');
      bt_show_icon.removeClass('fa-eye-slash');
      bt_show_icon.addClass('fa-eye');
      bt_show_icon.parent().tooltip('hide')
                  .attr('data-bs-original-title', 'Show password')
                  .tooltip('show');
    }
  });

  //Generate Password
  $('#genpw').click(function(e){
    const pw_chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz{}()[]<>/\#,:;.$=+-*?!@#$%&';
    const pw_input = $(this).parent().parent().find('#passphrase');
    const bt_show_icon = $(this).parent().find('.input-group-text > i');
    var password = '';

    for (var i = 0; i < 30; i++) {
      // generate password
      gen = pw_chars.charAt(Math.floor(Math.random() * pw_chars.length));
      password += gen;
    }
    pw_input.attr('type','text');
    pw_input.val(password);
    bt_show_icon.removeClass('fa-eye');
    bt_show_icon.addClass('fa-eye-slash');
    bt_show_icon.parent().tooltip('hide').attr('data-bs-original-title', 'Hide password');
    pw_input.focus();

    pw_input.one('blur', function(e) {
      if ($(this).attr('type') === 'text' && (e.relatedTarget !== undefined && e.relatedTarget  !== null)){
        $(this).attr('type', 'password')
        bt_show_icon.removeClass('fa-eye-slash');
        bt_show_icon.addClass('fa-eye');
        bt_show_icon.parent().tooltip('hide').attr('data-bs-original-title', 'Show password');
      }
    });
  });
  
  //Tests
  $('.ajax-get-file').click(function(e){
    e.preventDefault();
    var url = $(this).closest('form').attr('action');
    
    $.ajax({
      type: "POST",
      url: url,
      data: $(this).closest('form').serialize(),
      success: function(response, status, xhr) {
        
        var index = url.lastIndexOf("/") + 1;
        var filename = url.substr(index);
        
        var disposition = xhr.getResponseHeader('Content-Disposition');
        if (disposition && disposition.indexOf('attachment') !== -1) {
            var filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
            var matches = filenameRegex.exec(disposition);
            if (matches != null && matches[1]) filename = matches[1].replace(/['"]/g, '');
        }

        var type = xhr.getResponseHeader('Content-Type');
        var blob = new Blob([response], { type: type });
        
        console.log(type);

        if (typeof window.navigator.msSaveBlob !== 'undefined') {
            // IE workaround for "HTML7007: One or more blob URLs were revoked by closing the blob for which they were created. These URLs will no longer resolve as the data backing the URL has been freed."
            window.navigator.msSaveBlob(blob, filename);
        } else {
            var URL = window.URL || window.webkitURL;
            var downloadUrl = URL.createObjectURL(blob);

            if (filename) {
                // use HTML5 a[download] attribute to specify filename
                var a = document.createElement("a");
                // safari doesn't support this yet
                if (typeof a.download === 'undefined') {
                    window.location = downloadUrl;
                } else {
                    a.href = downloadUrl;
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                }
            } else {
                window.location = downloadUrl;
            }

            setTimeout(function () { URL.revokeObjectURL(downloadUrl); }, 100); // cleanup
        }
      }
    });    
  });
});