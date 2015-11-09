#!/usr/bin/perl
use warnings;
use strict;
use XML::Simple;
use Data::Dumper;

my $url = "http://freesvr:freesvr\@172.16.210.99:8080/manager/status?XML=true";
`wget -t 1 -T 3 '$url' -O 111.xml 1>/dev/null 2>&1`;
my $status = XMLin("111.xml");   

print Dumper($status);
my $traffic = $status->{"connector"}->{"http-8080"}->{"requestInfo"}->{"processingTime"};
print $traffic,"\n";


