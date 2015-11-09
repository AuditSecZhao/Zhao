#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use DBD::mysql;
use Crypt::CBC;
use MIME::Base64;

our $cipher = Crypt::CBC->new( -key => 'freesvr', -cipher => 'Blowfish', -iv => 'freesvr1', -header => 'none');
our $mysql_passwd = "JZ1EzZwjYXo=";
$mysql_passwd = decode_base64($mysql_passwd);

our $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root",$cipher->decrypt($mysql_passwd),{RaiseError=>1});
our $sqr = $dbh->prepare("show tables");
$sqr->execute();
while(my $ref = $sqr->fetchrow_hashref())
{
    print $ref->{"Tables_in_audit_sec"},"\n";
}
$sqr->finish();


