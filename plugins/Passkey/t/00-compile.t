use strict;
use warnings;

use FindBin;
use Test::More;

use lib qw(lib extlib), "$FindBin::Bin/../lib";

use_ok 'MT::Plugin::Passkey';

done_testing;
