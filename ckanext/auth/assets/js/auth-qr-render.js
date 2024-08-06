ckan.module("auth-qr-render", function () {
    'use strict';

    return {
        options: {
            value: null,
            size: 300
        },

        initialize() {
            console.log(this.options.value);

            if (!this.options.value) {
                console.error('Value is required for QR code rendering');
                return;
            }

            new QRious({
                element: this.el[0],
                size: this.options.size,
                value: this.options.value
            })
        }
    }
})
