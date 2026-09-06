use strict;
use warnings;
use Test::More;
use t::Util;

subtest "operational lifecycle test" => sub {
	my ($stderr, $stdout) = run_prog("./t/00util/test_operational");
	diag "STDERR:\n$stderr" if $stderr ne "";
	like $stdout, qr/===OPERATIONAL OK===/,
	  "graceful close diagnostics and client reconnect survive peer restart";
};

done_testing();
