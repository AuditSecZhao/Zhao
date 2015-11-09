#!/usr/bin/perl
use warnings;
use strict;

my $device_ip = "172.16.210.41";
my $nginx_port = 81;
my $connect = undef;
my $request = undef;

my $url = "http://$device_ip:$nginx_port/nginx_status";
if(system("wget -t 1 -T 3 '$url' -O /tmp/nginx_status_$device_ip 1>/dev/null 2>&1") != 0)
{                            
    print "get fail\n";
    unlink "/tmp/server_status_$device_ip";
    exit 1;
}                                                                           

open(my $fd_fr,"</tmp/nginx_status_$device_ip");
foreach my $line(<$fd_fr>)
{
    chomp $line;
    if($line =~ /Active connections\s*:\s*(\d+)/i)
    {
        $connect = $1;
    }

    if($line =~ /\s*(\d+)\s*(\d+)\s*(\d+)/i)
    {
        $request = $3;
    }
}

print "connect $connect, request $request\n";
