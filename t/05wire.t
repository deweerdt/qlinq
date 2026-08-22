#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use t::Util;

subtest 'versioned transport wire codec' => sub {
    my ($stderr, $stdout) = run_prog('./t/00util/test_transport_wire');
    like($stdout, qr/===TRANSPORT WIRE OK===/,
         'wire codec roundtrips and rejects malformed frames') or diag($stderr);
};

done_testing;
