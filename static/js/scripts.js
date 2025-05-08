$(document).ready(function () {
    // Register form submission
    $('#registerForm').submit(function (e) {
        e.preventDefault();
        const btn = $(this).find('button');
        btn.prop('disabled', true);

        $.ajax({
            type: 'POST',
            url: 'http://localhost:8080/api/register',
            contentType: 'application/json',
            data: JSON.stringify({
                username: $('#reg-username').val(),
                password: $('#reg-password').val()
            }),
            success: function (response) {
                $('#qrImage').attr('src', 'data:image/png;base64,' + response.qr_image);
                $('#totpSecret').text('Secret: ' + response.totp_secret);
                $('#downloadQr').attr('href', '/api/qrcode/' + response.username);
                $('#qrCard').show();

                $('#registerFeedback').html(`
                    <div class="alert alert-success">
                        ${response.message}
                    </div>
                `);
            },
            error: function (xhr) {
                $('#registerFeedback').html(`
                    <div class="alert alert-danger">
                        ${xhr.responseJSON?.error || 'Registration failed'}
                    </div>
                `);
            },
            complete: function () {
                btn.prop('disabled', false);
            }
        });
    });

    // Login form submission
    $('#loginForm').submit(function (e) {
        e.preventDefault();
        const btn = $(this).find('button');
        btn.prop('disabled', true);

        $.ajax({
            type: 'POST',
            url: 'http://localhost:8080/api/login',
            contentType: 'application/json',
            data: JSON.stringify({
                username: $('#login-username').val(),
                password: $('#login-password').val(),
                totp_code: $('#totp-code').val()
            }),
            success: function (response) {
                $('#loginFeedback').html(`
                    <div class="alert alert-success">
                        ${response.message}
                    </div>
                `);
            },
            error: function (xhr) {
                $('#loginFeedback').html(`
                    <div class="alert alert-danger">
                        ${xhr.responseJSON?.error || 'Login failed'}
                    </div>
                `);
            },
            complete: function () {
                btn.prop('disabled', false);
            }
        });
    });
});