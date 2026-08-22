use strict;
use warnings;
use Test::More;
use t::Util;

subtest "nonblocking UDS framing and permissions" => sub {
    my ($stderr, $stdout) = run_prog("./t/00util/test_data_uds");
    like($stdout, qr/===DATA UDS OK===/, "partial frames and queued output work");
};

done_testing();
