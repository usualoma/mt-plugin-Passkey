package MT::Plugin::Passkey;

use strict;
use warnings;
use utf8;

use Class::Method::Modifiers qw(install_modifier);
use MIME::Base64;
use MT::Util;

our @EXPORT_OK = qw(plugin translate);
use base qw(Exporter);

sub component {
    __PACKAGE__ =~ m/::([^:]+)\z/;
}

sub translate {
    MT->component(component())->translate(@_);
}

sub plugin {
    MT->component(component());
}

sub _insert_after_by_name {
    my ($tmpl, $name, $template_name) = @_;

    my $before = pop @{ $tmpl->getElementsByName($name) || [] }
        or return;
    foreach my $t (@{ plugin()->load_tmpl($template_name)->tokens }) {
        $tmpl->insertAfter($t, $before);
        $before = $t;
    }
}

sub template_param_login {
    my ($cb, $app, $param, $tmpl) = @_;
    $param->{plugin_passkey_version} = plugin()->version;
    _insert_after_by_name($tmpl, 'layout/chromeless.tmpl', 'login_footer.tmpl');
}

sub template_source_login_mt {
    my ($cb, $app, $tmpl) = @_;
    $$tmpl =~ s{(<input type="text" name="username"[^>]+)(/?>)}{$1 autocomplete="username webauthn"$2};
}

sub template_param_list_common {
    my ($cb, $app, $param, $tmpl) = @_;
    if ($app->param('_type') eq 'passkey') {
        my $user = $app->user;
        $param->{passkey_user_id}           = $user->id;
        $param->{passkey_user_name}         = $user->name;
        $param->{passkey_user_display_name} = $user->nickname || $app->user->name;
        $param->{passkey_exclude_ids}       = [map { $_->credential_id } $app->model('passkey')->load({ author_id => $user->id })];
        _insert_after_by_name($tmpl, 'page_content', 'list_common.tmpl');
    }
}

sub save_permission_filter {
    my ($cb, $app, $id) = @_;
    my $user = $app->user;
    return 1 if $user->is_superuser;
    $app->model('passkey')->exist({ id => $id, author_id => $user->id });
}

sub delete_permission_filter {
    my ($cb, $app, $obj) = @_;
    my $user = $app->user;
    return 1 if $user->is_superuser;
    $obj->author_id == $user->id;
}

sub pre_load_filtered_list {
    my ($cb, $app, $filter, $load_options, $cols) = @_;

    my $user = $app->user;

    return if $user->is_superuser;

    my %terms = (
        author_id => $user->id,
    );
    if (ref $load_options->{terms} eq 'ARRAY') {
        push @{ $load_options->{terms} }, '-and', \%terms;
    } else {
        $load_options->{terms} = +{ %{ $load_options->{terms} || {} }, %terms };
    }
}

sub _authen_webauthn {
    my $app = shift;

    require Authen::WebAuthn;
    require URI;

    my $origin = $app->base;
    my $host   = new URI($origin)->host;

    Authen::WebAuthn->new(
        rp_id  => $host,
        origin => $origin,
    );
}

sub save_passkey {
    my $app  = shift;
    my $user = $app->user;

    my $webauthn_rp = _authen_webauthn($app);

    my $challenge = $app->model('passkey_challenge')->validate_id(scalar $app->param('challenge'))
        or return $app->json_error(translate("Invalid challenge."));
    (my $challenge_b64 = MIME::Base64::encode($challenge, '')) =~ s/=+$//;
    my $registration_result = eval {
        $webauthn_rp->validate_registration(
            challenge_b64          => $challenge_b64,
            client_data_json_b64   => scalar $app->param('clientDataJSON'),
            attestation_object_b64 => scalar $app->param('attestationObject'),

            # TBD: Should we validate these?
            # requested_uv           => '',
            # token_binding_id_b64   => '',
        );
    };
    if (my $err = $@) {
        $err =~ s/ at .+//s;
        return $app->json_error(translate('Error validating registration: [_1]', $err));
    }

    my $passkey = $app->model('passkey')->new(
        id            => substr($registration_result->{credential_id}, 0, 255),
        credential_id => $registration_result->{credential_id},
        label         => scalar $app->param('label') || 'Passkey',
        author_id     => $user->id,
        public_key    => $registration_result->{credential_pubkey},
    );
    $passkey->save or return $app->json_error(translate("Failed to save passkey: [_1]", $passkey->errstr));

    return $app->json_result;
}

sub _invalid_credentials {
    my $app = shift;

    MT::Lockout->process_login_result(
        $app, $app->remote_ip, '',
        MT::Auth::INVALID_PASSWORD());

    $app->json_error(translate(@_));
}

sub login_passkey {
    my $app = shift;

    require MT::Auth;
    require MT::Lockout;
    return $app->json_error(translate("Invalid credential."))
        if MT::Lockout->is_locked_out($app, $app->remote_ip, '');

    my $passkey = $app->model('passkey')->load_by_credential_id(scalar $app->param('id'))
        or return _invalid_credentials($app, "Invalid credential.");

    my $webauthn_rp = _authen_webauthn($app);

    my $challenge = $app->model('passkey_challenge')->validate_id(scalar $app->param('challenge'))
        or return _invalid_credentials($app, "Invalid challenge.");
    (my $challenge_b64 = MIME::Base64::encode($challenge, '')) =~ s/=+$//;
    my $validation_result = eval {
        $webauthn_rp->validate_assertion(
            challenge_b64          => $challenge_b64,
            credential_pubkey_b64  => $passkey->public_key,
            client_data_json_b64   => scalar $app->param('clientDataJSON'),
            authenticator_data_b64 => scalar $app->param('authenticatorData'),
            signature_b64          => scalar $app->param('signature'),

            # TBD: Should we validate these?
            # stored_sign_count      => ...,
            # requested_uv           => ...,
            # extension_results      => ...,
            # token_binding_id_b64   => ...,
        );
    };
    if (my $err = $@) {
        return _invalid_credentials($app, 'Error validating authentication: [_1]', $err);
    }

    my $author = $app->model('author')->load($passkey->author_id)
        or return _invalid_credentials($app, "Invalid author.");

    MT::Auth->new_login($app, $author);
    $app->request('fresh_login', 1);
    $app->log({
        message => translate(
            "User '[_1]' (ID:[_2]) logged in successfully via passkey",
            $author->name, $author->id
        ),
        level    => MT::Log::INFO(),
        class    => 'author',
        category => 'login_user',
    });
    MT::Lockout->process_login_result(
        $app, $app->remote_ip, '',
        MT::Auth::NEW_LOGIN());

    my $remember = 0;    # TBD: Somehow get $remember set
    $app->start_session($author, $remember);

    # FIXME: MFA plugin requires mfa_verified to be set in the session.
    $app->session('mfa_verified', 1);
    $app->session->save;

    return $app->json_result({
        redirect_to => $app->mt_uri,
    });
}

sub challenge_passkey {
    my $app = shift;

    return $app->json_result({
        challenge => $app->model('passkey_challenge')->generate_id,
    });
}

1;
