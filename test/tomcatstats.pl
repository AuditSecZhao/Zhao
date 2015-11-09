#!/usr/bin/perl
#
# Tim Denike 1/4/07 - Please excuse this horriblie sloppy code...
#

use strict;
use XML::Simple;
#use Data::Dumper;

MAIN:
{
    my $host = shift;
    my $username = shift;
    my $password = shift;
    my $connector = shift or &usage;
    my $url = "http://$username:$password"."\@$host/manager/status?XML=true";

    my $xml = `GET $url`;

    my $status = XMLin($xml);

    #print Dumper($status);

    print "jvm_memory_free:$status->{jvm}->{memory}->{free} ";
    print "jvm_memory_max:$status->{jvm}->{memory}->{max} ";
    print "jvm_memory_total:$status->{jvm}->{memory}->{total} ";
    print "connector_max_time:$status->{connector}->{$connector}->{requestInfo}->{maxTime} ";
    print "connector_error_count:$status->{connector}->{$connector}->{requestInfo}->{errorCount} ";
    print "connector_bytes_sent:$status->{connector}->{$connector}->{requestInfo}->{bytesSent} ";
    print "connector_processing_time:$status->{connector}->{$connector}->{requestInfo}->{processingTime} ";
    print "connector_request_count:$status->{connector}->{$connector}->{requestInfo}->{requestCount} ";
    print "connector_bytes_received:$status->{connector}->{$connector}->{requestInfo}->{bytesReceived} ";
    print "connector_current_thread_count:$status->{connector}->{$connector}->{threadInfo}->{currentThreadCount} ";
    print "connector_min_spare_threads:$status->{connector}->{$connector}->{threadInfo}->{minSpareThreads} ";
    print "connector_max_threads:$status->{connector}->{$connector}->{threadInfo}->{maxThreads} ";
    print "connector_max_spare_threads:$status->{connector}->{$connector}->{threadInfo}->{maxSpareThreads} ";
    print "connector_current_threads_busy:$status->{connector}->{$connector}->{threadInfo}->{currentThreadsBusy} ";
}

sub usage ()
{
   print "$0 [host:port] [username] [password] [connector]\n";
   print "   IE:  $0 app1:8081 admin password http-8080\n";
   exit 1;
}
