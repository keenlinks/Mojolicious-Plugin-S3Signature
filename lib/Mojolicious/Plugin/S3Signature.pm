package Mojolicious::Plugin::S3Signature;

use Mojo::Base 'Mojolicious::Plugin';
use Carp;
use Digest::SHA qw(hmac_sha256 hmac_sha256_hex sha256_hex);
use Mojo::Date;
use Mojo::JSON qw(encode_json);
use Mojo::Util qw(b64_encode monkey_patch slugify);

our $VERSION = '0.01_1';

# Required
has access_key => sub { croak 'Parameter "access_key" is mandatory in the constructor.' };
has access_key_id => sub { croak 'Parameter "access_key_id" is mandatory in the constructor.' };
has bucket => sub { croak 'Parameter "bucket" is mandatory in the constructor.' };

# Defaults if not provided
has protocol => sub { 'https://' };
has region => sub { 'us-east-1' };

# Defaults
has aws_auth_alg => 'AWS4-HMAC-SHA256';
has aws_host => 's3.amazonaws.com';
has aws_request => 'aws4_request';
has aws_service => 's3';
has policy_expiration => 900; # 15 minutes

has bucket_path => sub { $_[0]->bucket . '.' . $_[0]->aws_host };
has bucket_url => sub { $_[0]->protocol . $_[0]->bucket_path };

monkey_patch 'Mojo::Date', to_ymd => sub {
	my @gmtime = gmtime shift->epoch;
	sprintf '%04d%02d%02d', $gmtime[5] + 1900, $gmtime[4] + 1, $gmtime[3];
};

monkey_patch 'Mojo::Date', to_ymdhms => sub {
	my @gmtime = gmtime shift->epoch;
	sprintf '%04d%02d%02dT%02d%02d%02dZ', $gmtime[5] + 1900, $gmtime[4] + 1, $gmtime[3], $gmtime[2], $gmtime[1], $gmtime[0];
};

sub register {
	my ( $self, $app, $conf ) = @_;

	$self->access_key( $conf->{access_key} );
	$self->access_key_id( $conf->{access_key_id} );
	$self->bucket( $conf->{bucket} );

	$self->protocol( $conf->{protocol} ) if $conf->{protocol};
	$self->region( $conf->{region} ) if $conf->{region};

	$app->helper( s3_browser_policy => sub {
		my ( $c, $params ) = @_;
		my $date = Mojo::Date->new;
		my $credential = $self->_credential( $date );

		my $policy = encode_json({
			expiration => Mojo::Date->new( time + $self->policy_expiration )->to_datetime,
			conditions => [
				{bucket => $self->bucket},
				{'x-amz-algorithm' => $self->aws_auth_alg},
				{'x-amz-credential' => $credential},
				{'x-amz-date' => $date->to_ymdhms},
				{acl => 'public-read'},
				{key => $params->{filename}},
				{'content-type' => $params->{filetype}},
				['content-length-range', 0, $params->{filesize}],
				{success_action_status => '200'}
			]
		});

		my $base64_policy = b64_encode $policy, '';

		return {
			'x-amz-algorithm' => $self->aws_auth_alg,
			'x-amz-credential' => $credential,
			'x-amz-date' => $date->to_ymdhms,
			acl => 'public-read',
			key => $params->{filename},
			'content-type' => $params->{filetype},
			success_action_status => '200',
			policy => $base64_policy,
			'x-amz-signature' => $self->_sign_the_string( $base64_policy ),
		};
	});

	$app->helper( s3_bucket_url => sub { $self->bucket_url });

	for my $method (qw/ delete get head options patch post put /) {
		$app->helper( "s3_sign_$method" => sub {
			$self->_sign_method( uc $method, @_[ 1 .. $#_ ] )
		});
	}

	$app->helper( s3_sign_copy => sub {
		$self->_sign_method( 'PUT', $_[2], {
			'x-amz-copy-source' => $self->bucket . '/' . $_[1]
		});
	});

	$app->helper( s3_sign_upload => sub {
		# Pass upload as a reference.
		my $upload = ${ $_[2] };
		$self->_sign_method( 'PUT', $_[1], {
			'content-length' => $upload->size,
			'content-type' => $upload->headers->content_type,
			'x-amz-content-sha256' => sha256_hex( $upload->slurp ),
		});
	});
}

sub _sign_method {
	my ( $self, $method ) = ( shift, shift );
	return [ $self->_object_url( $_[0] ), $self->_headers( $method, @_[ 0 .. $#_ ] ) ];
}

sub _auth_header {
	my ( $self, $method, $date, $s3_object_name, $raw_headers ) = @_;

	my $headers = {};
	map { $headers->{ slugify $_ } = $raw_headers->{$_} } keys %$raw_headers;

	my $string_to_sign = $self->_string_to_sign( $self->_canonical_request( $method, $s3_object_name, $headers ), $date );

	my $signature = $self->_sign_the_string( $string_to_sign, $self->access_key, $date->to_ymd );

	my $auth = $self->aws_auth_alg;
	$auth .= ' Credential=' . $self->_credential( $date ) . ',';
	$auth .= 'SignedHeaders=' . ( join ';', sort keys %$headers ) . ',';
	$auth .= 'Signature=' . $signature;
}

sub _canonical_request {
	my ( $self, $method, $s3_object_name, $headers ) = @_;
	my $canonical_request = $method . "\n";
	$canonical_request .=  '/' . $s3_object_name . "\n";
	$canonical_request .= "\n";
	$canonical_request .= $_ . ':' . $headers->{$_} . "\n" for sort keys %$headers;
	$canonical_request .= "\n" . ( join ';', sort keys %$headers ) . "\n";
	$canonical_request .= $headers->{'x-amz-content-sha256'};
}

sub _credential {
	$_[0]->access_key_id . '/' . $_[1]->to_ymd . '/' . $_[0]->region . '/' . $_[0]->aws_service . '/' . $_[0]->aws_request;
}

sub _headers {
	my ( $self, $method, $s3_object_name, $headers ) = @_;
	my $date = Mojo::Date->new;
	$headers->{date} = $date->to_string;
	$headers->{host} = $self->bucket_path;
	$headers->{'x-amz-content-sha256'} = sha256_hex( 'UNSIGNED-PAYLOAD' ) unless defined $headers->{'x-amz-content-sha256'};
	$headers->{authorization} = $self->_auth_header( $method, $date, $s3_object_name, $headers );
	return $headers;
}

sub _object_url { $_[0]->bucket_url . '/' . $_[1] }

sub _signing_key {
	my $self = shift;
	hmac_sha256( $self->aws_request,
		hmac_sha256( $self->aws_service,
			hmac_sha256( $self->region,
				hmac_sha256( Mojo::Date->new->to_ymd, 'AWS4' . $self->access_key )
			)
		)
	);
}

sub _sign_the_string { hmac_sha256_hex( $_[1], $_[0]->_signing_key ) }

sub _string_to_sign {
	my ( $self, $canonical_request, $date ) = @_;
	my $string_to_sign = $self->aws_auth_alg . "\n";
	$string_to_sign .= $date->to_string . "\n";
	$string_to_sign .= $date->to_ymd . '/' . $self->region . '/' . $self->aws_service . '/' . $self->aws_request . "\n";
	$string_to_sign .= sha256_hex( $canonical_request );
}

1;
__END__

=encoding utf-8

=head1 NAME

Mojolicious::Plugin::S3Signature - Mojolicious plugin for AWS Signature Version 4.

=head1 VERSION

0.01_1

=head1 SOURCE REPOSITORY

L<http://github.com/keenlinks/Mojolicious-Plugin-S3Signature>

=head1 AUTHOR

Scott Kiehn E<lt>sk.keenlinks@gmail.comE<gt>

=head1 COPYRIGHT

Copyright 2018 - Scott Kiehn

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

=cut
