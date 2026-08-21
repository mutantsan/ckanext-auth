ckan.module("auth-2fa-manage", function () {
    'use strict';

    return {
        options: {
            enabled: true,
        },

        initialize() {

            $.proxyAll(this, /_/);

            if (!this.options.enabled) {
                return;
            }

            // Bind events
            $('#mfa-show-qr-code').on('click', function(e) {
              e.preventDefault();
              // Remove the hidden class
              $('#mfa-qr-code-secret').removeClass('hidden');
              // Hide button
              $('#mfa-show-qr-code-fieldset').addClass('hidden');
            });
        },
    }
})
