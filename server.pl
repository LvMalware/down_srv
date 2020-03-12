#!/usr/bin/env perl

use strict;
use threads;
use warnings;
use Thread::Queue;
use IO::Socket::INET;
use Digest::SHA qw(sha256_hex);

#'password'
my $passwd = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";

$| = 1;

my $links = Thread::Queue->new;
my $down_th = threads->new(\&downloading);
my $serv_th = threads->new(\&server_loop);
$down_th->join();
$serv_th->join();

sub server_loop
{
    
    my $server = IO::Socket::INET->new(
        Listen    => 5,
        LocalAddr => "0.0.0.0",
        LocalPort => 6660,
        Proto     => "tcp"
    ) || die "Can't create the server";

    #only a client at time
    while (1)
    {
        my $cli_sock = $server->accept();
        my $cli_host = $cli_sock->peerhost();
        my $cli_port = $cli_sock->peerport();
        print "[+] Accepted connection from $cli_host:$cli_port\n";

        #Authentication
        $cli_sock->send("Password: ");
        chomp(my $password=<$cli_sock>);
        (sha256_hex($password) eq $passwd) || ($cli_sock->close() && next);
        
        $cli_sock->send("Enter the links to download, one per line.\n> ");
        while (my $link = <$cli_sock>)
        {
            #Receive and enqueue the links
            chomp($link);
            $links->enqueue($link);
            $cli_sock->send("> ");
            print "[+] Added to queue: $link\n";
        }
        print "[+] Client disconnected.\n";
    }
}

sub downloading
{
    while (1)
    {
        #get the next link on the queue and download it using wget
        if (defined(my $link = $links->dequeue()))
        {
            system("wget -q '$link'");
            print "[+] Download finished: $link\n"
        }
    }
}
