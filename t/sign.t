# -*- Mode: Perl; -*-

use strict;

use Test;
use Crypt::OpenSSL::DSA;

BEGIN { plan tests => 21 }

my $message = "foo bar";

my $dsa = Crypt::OpenSSL::DSA->generate_parameters( 512, "foo" );
$dsa->generate_key;
my $dsa_sig1 = $dsa->sign($message);
my $dsa_sig_obj1 = $dsa->do_sign($message);
my $bogus_sig = $dsa_sig1;
$bogus_sig =~ s!.a$!ba!;
$bogus_sig =~ s!.$!a!;

ok(length($dsa->get_pub_key),64);
ok(length($dsa->get_p),64);
ok(length($dsa->get_q),20);
ok(length($dsa->get_g),64);

ok(length($dsa_sig_obj1->get_r), 20);
ok(length($dsa_sig_obj1->get_s), 20);

ok($dsa->verify($message, $dsa_sig1), 1);
ok($dsa->verify($message, $bogus_sig), 0);

ok($dsa->do_verify($message, $dsa_sig_obj1), 1);

ok($dsa->write_params("dsa.param.pem"), 1);
ok($dsa->write_pub_key("dsa.pub.pem"), 1);
ok($dsa->write_priv_key("dsa.priv.pem"), 1);

my ($priv_key_str, $pub_key_str);
{
  local($/) = undef;
  open PRIV, "dsa.priv.pem";
  $priv_key_str = <PRIV>;
  close PRIV;
  open PUB, "dsa.pub.pem";
  $pub_key_str = <PUB>;
  close PUB;
}

my $dsa2 = Crypt::OpenSSL::DSA->read_priv_key("dsa.priv.pem");
my $dsa_sig2 = $dsa2->sign($message);

my $dsa3 = Crypt::OpenSSL::DSA->read_pub_key("dsa.pub.pem");

my $dsa4 = Crypt::OpenSSL::DSA->read_priv_key_str($priv_key_str);
my $dsa5 = Crypt::OpenSSL::DSA->read_pub_key_str($pub_key_str);

ok($dsa->verify($message, $dsa_sig2), 1);
ok($dsa2->verify($message, $dsa_sig2), 1);
ok($dsa2->verify($message, $dsa_sig1), 1);
ok($dsa3->verify($message, $dsa_sig1), 1);
ok($dsa3->verify($message, $dsa_sig2), 1);
ok($dsa4->verify($message, $dsa_sig2), 1);
ok($dsa4->verify($message, $dsa_sig1), 1);
ok($dsa5->verify($message, $dsa_sig1), 1);
ok($dsa5->verify($message, $dsa_sig2), 1);

unlink("dsa.param.pem");
unlink("dsa.priv.pem");
unlink("dsa.pub.pem");

