package MT::Plugin::Passkey::PasskeyChallenge;

use strict;
use warnings;

use MT::Util::UniqueID;
use base qw( MT::Object );

__PACKAGE__->install_properties({
    column_defs => {
        'id' => 'string(128) not null',
    },
    indexes => {
        created_on => 1,
    },
    audit       => 1,
    datasource  => 'passkey_challenge',
    primary_key => 'id',
});

sub class_label {
    MT->translate("Passkey Challenge");
}

sub class_label_plural {
    MT->translate("Passkey Challenges");
}

sub generate_id {
    my $class = shift;

    $class->purge_expired;

    my $id;
    do {
        $id = MT::Util::UniqueID::create_sha512_id;
    } while ($class->load($id));

    $class->new(id => $id)->save or die $class->errstr;

    $id;
}

sub purge_expired {
    my $class = shift;
    # my $ts    = MT::Util::epoch2ts(time - 60 * 60 * 24);
    # $class->remove({ created_on => [ undef, $ts ] });
}

sub validate_id {
    my ($class, $id) = @_;
    return unless $id;
    my $obj = $class->load($id);
    $obj->remove if $obj;
    return $obj ? $id : ();
}

1;
__END__
