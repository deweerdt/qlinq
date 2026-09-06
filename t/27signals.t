use strict;
use warnings;
use Test::More;
use t::Util;

subtest "process lifecycle signals" => sub {
	my ($stderr, $stdout) = run_prog("sh t/00util/test_signals.sh");
	diag "STDERR:\n$stderr" if $stderr ne "";
	like $stdout, qr/===SIGNALS OK===/,
	  "app and daemon atomically reload TLS credentials on SIGHUP";
};

done_testing();
