#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use t::Util;

subtest 'decomposed transport components' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_transport_components');
    like($stdout, qr/===TRANSPORT COMPONENTS OK===/,
         'component ownership and lookup tests pass') or diag($stderr);
};

done_testing;
