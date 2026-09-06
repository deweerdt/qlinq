use strict;
use warnings;
use Test::More;
use t::Util;

subtest "mutual TLS policy" => sub {
	my ($stderr, $stdout) = run_prog("./t/00util/test_tls");
	diag "STDERR:\n$stderr" if $stderr ne "";
	like $stdout, qr/===TLS OK===/,
	  "trusted peer authenticates and an untrusted certificate is rejected";
};

done_testing();
