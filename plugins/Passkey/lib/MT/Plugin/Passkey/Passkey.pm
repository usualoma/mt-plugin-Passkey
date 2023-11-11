package MT::Plugin::Passkey::Passkey;

use strict;
use warnings;

use MT::Plugin::Passkey qw(translate);

use base qw( MT::Object );

__PACKAGE__->install_properties({
    column_defs => {
        'id'            => 'string(255) not null',
        'credential_id' => 'string(1330) not null',
        'author_id'     => {
            type     => 'integer',
            not_null => 1,
            label    => 'Author',
        },
        'label' => {
            type     => 'string',
            size     => 255,
            not_null => 1,
            label    => 'Label',
        },
        'public_key' => {
            type => 'text',
        },
    },
    indexes => {
        author_id  => 1,
        created_on => 1,
    },
    child_of    => 'MT::Author',
    audit       => 1,
    datasource  => 'passkey',
    primary_key => 'id',
});

sub class_label {
    translate("Passkey");
}

sub class_label_plural {
    translate("Passkeys");
}

sub load_by_credential_id {
    my $class           = shift;
    my ($credential_id) = @_;
    my ($obj)           = grep { $_->credential_id eq $credential_id } $class->load({ id => substr($credential_id, 0, 255) });
    $obj;
}

1;
__END__
