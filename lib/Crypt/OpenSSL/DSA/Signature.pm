=head1 NAME

  Crypt::OpenSSL::DSA::Signature - Digital Signature Object

=head1 SYNOPSIS

  use Crypt::OpenSSL::DSA;
  my $dsa_priv = Crypt::OpenSSL::DSA->read_priv_key( $filename );
  my $sig_obj = $dsa_priv->do_sign($message);
  my $dsa_pub = Crypt::OpenSSL::DSA->read_pub_key( $filename );
  my $valid = $dsa_pub->do_verify($message, $sig_obj);

  my $r = $sig_obj->get_r;
  my $s = $sig_obj->get_s;

=head1 OBJECT METHODS

=item $r = $sig_obj->get_r;

Gets first member of signature pair.

=item $s = $sig_obj->get_s;

Gets second member of signature pair.

=head1 AUTHOR

T.J. Mather, E<lt>tjmather@tjmather.comE<gt>

=head1 SEE ALSO

L<Crypt::OpenSSL::DSA>

=cut
