ckan.module("auth-login-form", function () {
    'use strict';

    return {
        options: {
            enabled: true,
            mfaMethod: null
        },

        initialize() {
            $.proxyAll(this, /_/);

            if (!this.options.enabled) {
                return;
            }

            this.form = this.el;
            this.nextBtn = this.form.find("button[type='submit']");
            this.submitBtn = this.form.find("#mfa-submit");
            this.loginForm = $("#login-form");
            this.mfaForm = $("#mfa-form");
            this.mfaEmailSent = false;

            // Bind events
            this.nextBtn.on("click", this._onNextBtnClick);
            this.submitBtn.on("click", this._onSubmitBtnClick);
        },

        _onNextBtnClick: function (e) {
            e.preventDefault();

            this.submitBtn.prop("disabled", true);
            this.loginForm.hide();
            this.mfaForm.show();

            if (this.mfaForm.is(":visible")) {
                const url = this.options.mfaMethod === "email"
                    ? "/mfa/send_verification_code"
                    : "/mfa/init_qr_code";

                $.ajax({
                    url: url,
                    method: "POST",
                    data: this.form.serialize(),
                    success: this._onSuccessRequest,
                    error: this._onErrorRequest,
                    complete: () => {
                        this.submitBtn.prop("disabled", false);
                    }
                });
            }
        },

        _onSuccessRequest: function (data) {
            this.mfaEmailSent = true;
        },

        _onErrorRequest: function (data) {
            console.error(data);
        },

        _onSubmitBtnClick: function (e) {
            e.preventDefault();

            this.submitBtn.prop("disabled", true);

            $.ajax({
                url: this.sandbox.url("/api/action/auth_2fa_validate_code"),
                method: "POST",
                data: this.form.serialize(),
                success: this._onSuccessRequest,
                error: this._onErrorRequest,
                complete: () => {
                    this.submitBtn.prop("disabled", false);
                }
            });
        }
    }
})
