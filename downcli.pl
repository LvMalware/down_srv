#!/usr/bin/env perl

use strict;
use threads;
use warnings;
use MIME::Base64;
use Math::BigInt;
use Thread::Queue;
use IO::Socket::INET;
use Crypt::Mode::CBC;
use ntheory qw(powmod);
use Digest::SHA qw(sha512_hex sha256_hex);

my $secret_password = "";

sub random_bytes { join '', map { chr rand 255 } 1 .. $_[0] || 16}

sub aes_encrypt
{
	my $iv = random_bytes();
	encode_base64($iv . Crypt::Mode::CBC->new('AES', 1)->encrypt($_[0], $secret_password, $iv)) =~ s/\n//r
}

sub aes_decrypt
{
	my $ciphertext = decode_base64($_[0]);
	my ($iv, $data) = (substr($ciphertext, 0, 16), substr($ciphertext, 16));
	Crypt::Mode::CBC->new('AES', 1)->decrypt($data, $secret_password, $iv)
}

sub rsa_encrypt
{
	my ($str, $e, $n) = @_;
	my $m = Math::BigInt->from_bytes($str);
	Math::BigInt->new(powmod($m, $e, $n))->to_hex()
}

my ($target, $port) = @ARGV;

die "No target host" unless $target;
$port = 6666 unless $port;

my $client = IO::Socket::INET->new(
	PeerHost => $target,
	PeerPort => $port,
	Proto    => 'tcp',
) || die "Can't connect to $target:$port";

$| = 1;

chomp(my $rsa_key = <$client>);
my ($e, $n) = split /,/, $rsa_key;
print "Password: ";
chomp(my $password = <STDIN>);
$client->send(rsa_encrypt($password, $e, $n) . "\n");
$secret_password = random_bytes();
$client->send(rsa_encrypt($secret_password, $e, $n) . "\n");
my $welcome = <$client>;
die "Wrong password" unless $welcome;
print aes_decrypt($welcome) . "\n";
while (1)
{
	print "LINK: ";
	chomp(my $link = <STDIN>);
	$client->send(aes_encrypt($link) . "\n");
}
