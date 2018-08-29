use Mojo::Base -strict;

use Test::More;
use Mojolicious::Lite;
use Test::Mojo;

plugin 'Mojolicious::Plugin::S3Signature';

my $t = Test::Mojo->new;
my $c = $t->app->build_controller;

done_testing();
