#!/usr/bin/env perl

use strict;
use threads;
use warnings;
use MIME::Base64;
use Math::BigInt;
use Thread::Queue;
use IO::Socket::INET;
use Crypt::Mode::CBC;
use ntheory qw(invmod lcm gcd powmod);
use Digest::SHA qw(sha512_hex sha256_hex);
use Math::Prime::Util qw(random_strong_prime);

#password
my $password = "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86";

$| = 1;

my $server = IO::Socket::INET->new(
	LocalAddr => '0.0.0.0',
	LocalPort => 6666,
	Proto	  => 'tcp',
	Reuse     => 0,
	Listen	  => 5
	) || die "Can't create the server!";

my $download_queue  = Thread::Queue->new;
my $download_thread = threads->new(\&download_loop);
my $secret_password = "";

sub random_bytes { join '', map { chr rand 255 } 1 .. $_[0] || 16}

sub aes_encrypt
{
	my $iv = random_bytes();
	encode_base64($iv . Crypt::Mode::CBC->new('AES', 1)->encrypt($_[0], $secret_password, $iv)) =~ s/\n//r;
}

sub aes_decrypt
{
	my $ciphertext = decode_base64($_[0]);
	my ($iv, $data) = (substr($ciphertext, 0, 16), substr($ciphertext, 16));
	Crypt::Mode::CBC->new('AES', 1)->decrypt($data, $secret_password, $iv)
}

sub generate_rsa_keypair
{
	my ($keysize) = @_;
	$keysize = 4096 unless $keysize;
	print "[+] Generating a new RSA keypair of $keysize bytes...\n";
	my ($p, $q) = (random_strong_prime($keysize / 2), random_strong_prime($keysize/2));
	my $n = $p * $q;
	my $t = lcm($p - 1, $q - 1);
	my $e = 3;
	$e ++ while gcd($e, $t) != 1;
	my $d = invmod($e, ($p - 1) * ($q - 1));
	($e, $d, $n)
}

sub rsa_encrypt
{
	my ($str, $e, $n) = @_;
	my $m = Math::BigInt->from_bytes($str);
	Math::BigInt->new(powmod($m, $e, $n))->to_hex()
}

sub rsa_decrypt
{
	my ($enc, $d, $n) = @_;
	my $c = Math::BigInt->new("0x$enc");
	Math::BigInt->new(powmod($c, $d, $n))->to_bytes()
}

while (1)
{
	my $client = $server->accept();
	print "[+] Accepted connection from " . $client->peerhost() . "\n";
	my ($e, $d, $n) = generate_rsa_keypair();
	$client->send("$e,$n\n");
	chomp(my $passwd = <$client>);
	(sha512_hex(rsa_decrypt($passwd, $d, $n)) eq $password) || ($client->close() && next);
	print "[+] Authenticated.\n";
	chomp(my $secpwd = <$client>);
	$secret_password = rsa_decrypt($secpwd, $d, $n);
	print "[+] Got secret password\n";
	$client->send(aes_encrypt("Welcome!\nEnter the links to download, one per line.") . "\n");
	while (my $link = <$client>)
	{
		chomp($link);
		$link = aes_decrypt($link);
		$download_queue->enqueue($link) if $link;
		print "[+] Added new item to queue\n" if $1;
	}
	print "[+] Client disconnected.\n";
}

sub download_loop
{
	while (1)
	{
		if (defined(my $link = $download_queue->dequeue()))
		{
			if ($link =~ /\.m3u8/) #download of videos
			{
				system("youtube-dl '$link' &>/dev/null &")
			}
			elsif ($link =~ /^magnetic\:\?/) #magnetic links
			{
				system("aria2c '$link' &>/dev/null &")
			}
			else #everything else
			{
				system("wget -c '$link' &>/dev/null &")
			}
		}
	}
}
