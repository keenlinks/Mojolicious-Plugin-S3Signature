package Mojolicious::Plugin::S3Signature;

use Mojo::Base 'Mojolicious::Plugin';
use Carp;
use Digest::SHA qw(hmac_sha256 hmac_sha256_hex sha256_hex);
use Mojo::Date;
use Mojo::Util qw(monkey_patch slugify);

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

#has method => sub { { DELETE => 'DELETE', GET => 'GET', PUT => 'PUT' } };
has bucket_path => sub { $_[0]->bucket . '.' . $_[0]->aws_host };
has bucket_url => sub { $_[0]->protocol . $_[0]->bucket_path };

monkey_patch 'Mojo::Date', to_ymd => sub {
	my @gmtime = gmtime shift->epoch;
	sprintf '%04d%02d%02d', $gmtime[5] + 1900, $gmtime[4] + 1, $gmtime[3];
};

sub register {
	my ( $self, $app, $conf ) = @_;

	$self->access_key( $conf->{access_key} );
	$self->access_key_id( $conf->{access_key_id} );
	$self->bucket( $conf->{bucket} );

	$self->protocol( $conf->{protocol} ) if $conf->{protocol};
	$self->region( $conf->{region} ) if $conf->{region};

	for my $method (qw/ delete get head options patch post put /) {
		$app->helper( "s3_sign_$method" => sub {
			$self->_sign_method( uc $method, @_[ 1 .. $#_ ] )
		});
	}

	$app->helper( s3_sign_upload => sub {
		my $upload = $_[2]->$*;
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
