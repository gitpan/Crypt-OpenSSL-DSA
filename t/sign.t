# $Id: $

use strict;

use Test;
use Crypt::OpenSSL::DSA;

BEGIN { plan tests => 14 }

my $message = "foo bar";

my $dsa = Crypt::OpenSSL::DSA->generate_parameters( 512, "foo" );
$dsa->generate_key;
my $dsa_sig1 = $dsa->sign($message);
my $bogus_sig = $dsa_sig1;
$bogus_sig =~ s!.a$!ba!;
$bogus_sig =~ s!.$!a!;

ok(length($dsa->get_pub_key),64);
ok(length($dsa->get_p),64);
ok(length($dsa->get_q),20);
ok(length($dsa->get_g),64);

ok($dsa->verify($message, $dsa_sig1), 1);
ok($dsa->verify($message, $bogus_sig), 0);

ok($dsa->write_params("dsa.param.pem"), 1);
ok($dsa->write_pub_key("dsa.pub.pem"), 1);
ok($dsa->write_priv_key("dsa.priv.pem"), 1);

my $dsa2 = Crypt::OpenSSL::DSA->read_priv_key("dsa.priv.pem");
my $dsa_sig2 = $dsa2->sign($message);

my $dsa3 = Crypt::OpenSSL::DSA->read_pub_key("dsa.pub.pem");

ok($dsa->verify($message, $dsa_sig2), 1);
ok($dsa2->verify($message, $dsa_sig2), 1);
ok($dsa2->verify($message, $dsa_sig1), 1);
ok($dsa3->verify($message, $dsa_sig1), 1);
ok($dsa3->verify($message, $dsa_sig2), 1);

unlink("dsa.param.pem");
unlink("dsa.priv.pem");
unlink("dsa.pub.pem");

