#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use DBD::mysql;
use RRDs;
use POSIX qw/ceil floor/;

our $debug = 1;
our $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});

our $utf8 = $dbh->prepare("set names utf8");
$utf8->execute();
$utf8->finish();

#our $sqr_truncate = $dbh->prepare("truncate local_status_err");
#$sqr_truncate->execute();
#$sqr_truncate->finish();

our $time_now_utc = time;
my($min,$hour,$mday,$mon,$year) = (localtime $time_now_utc)[1..5];
($min,$hour,$mday,$mon,$year) = (sprintf("%02d", $min),sprintf("%02d", $hour),sprintf("%02d", $mday),sprintf("%02d", $mon + 1),$year+1900);
our $time_now_str = "$year$mon$mday$hour$min"."00";

my $ssh_conn = int(`ps -ef | grep -v 'grep' | grep -c 'ssh-audit'`) -1;
$ssh_conn = $ssh_conn < 0 ? 0 : $ssh_conn;
$ssh_conn = ceil($ssh_conn/2);
&normal_insert($ssh_conn,'ssh并发数');

my $telnet_conn = int(`ps -ef | grep -v 'grep' | grep -c 'telnet'`) -1;
$telnet_conn = $telnet_conn < 0 ? 0 : $telnet_conn;
$telnet_conn = ceil($telnet_conn);
&normal_insert($telnet_conn,'telnet并发数');

my $graph_conn = int(`ps -ef | grep -v 'grep' | grep -c 'Freesvr_RDP'`) -1;
$graph_conn = $graph_conn < 0 ? 0 : $graph_conn;
&normal_insert($graph_conn,'图形会话并发数');

my $ftp_conn = int(`ps -ef | grep -v 'grep' | grep -c 'ftp-audit'`) -1;
$ftp_conn = $ftp_conn < 0 ? 0 : $ftp_conn;
&normal_insert($ftp_conn,'ftp连接数');

my $db_conn = int(`ps -ef | grep -v 'grep' | grep -c 'freesvr_pcap_audit.pl'`);
&normal_insert($ftp_conn,'数据库并发数');

my $cpu = `/usr/bin/top -b -n 1 | head -n 5 | grep -i 'cpu'`;
if($cpu =~ /(\d+\.\d+)%id/i) {$cpu = $1;}
$cpu = 100 -$cpu;
&normal_insert($cpu,'cpu');

my $memory = `free | grep -i 'mem'`;
my($total,$used,$buffers,$cache) = (split /\s+/,$memory)[1,2,5,6];
$memory = ceil(($used-$buffers-$cache)/$total*100);
&normal_insert($memory,'memory');

my $swap = `free | grep -i 'swap'`;
($total,$used) = (split /\s+/,$swap)[1,2];
$swap = ceil($used/$total*100);
&normal_insert($swap,'swap');

my $disk = `df | grep '/\$'`;
$disk = (split /\s+/,$disk)[4];
if($disk =~ /(\d+)%/){$disk = $1;}
&normal_insert($disk,'disk');

my @mysql_linknums = split /\n/,`mysqladmin processlist`;
my $mysql_linknum = 0;
foreach(@mysql_linknums)
{
	if($_ =~ /^\+/){next;}
	my $temp = (split /\|/,$_)[1];
	if($temp =~ /\d+/){++$mysql_linknum;}
}
&normal_insert($mysql_linknum,'mysql连接数');

my $http_link = int(`netstat -an | grep 443 | grep -c ESTABLISHED`);
&normal_insert($http_link,'http连接数');

my $tcp_link = int(`netstat -tn | grep -c ESTABLISHED`);
&normal_insert($tcp_link,'tcp连接数');

=pod
defined(my $pid = fork) or die "cannot fork:$!";
unless($pid)
{ 
	exec "/home/wuxiaolong/3_status/status_warning.pl",@abnormal_val;
}

our $eth0_in_now = -1;our $eth0_out_now = -1;our $eth1_in_now = -1;our $eth1_out_now = -1;
our $eth0_in_value = -1;our $eth0_out_value = -1;our $eth1_in_value = -1;our $eth1_out_value = -1;
our $eth0_info = `/sbin/ifconfig eth0 2>&1| grep -i 'RX byte'`;
if(defined $eth0_info && $eth0_info =~ /RX\s*bytes\s*:\s*(\d+)/i){$eth0_in_now = $1;}
if(defined $eth0_info && $eth0_info =~ /TX\s*bytes\s*:\s*(\d+)/i){$eth0_out_now = $1;}

our $eth1_info = `/sbin/ifconfig eth1 2>&1| grep -i 'RX byte'`;
if(defined $eth1_info && $eth1_info =~ /RX\s*bytes\s*:\s*(\d+)/i){$eth1_in_now = $1;}
if(defined $eth1_info && $eth1_info =~ /TX\s*bytes\s*:\s*(\d+)/i){$eth1_out_now = $1;}

if($last_datetime != -1 && $eth0_in_now != -1 && $eth0_in_last != -1)
{
	$eth0_in_value = ($eth0_in_now-$eth0_in_last)/($time_now_utc-$last_datetime)*8;
	$eth0_out_value = ($eth0_out_now-$eth0_out_last)/($time_now_utc-$last_datetime)*8;
	if($eth0_in_value < 0){$eth0_in_value = -1;}
	if($eth0_out_value < 0){$eth0_out_value = -1;}
}

if($last_datetime != -1 && $eth1_out_now != -1 && $eth1_in_last != -1)
{
	$eth1_in_value = ($eth1_in_now-$eth1_in_last)/($time_now_utc-$last_datetime)*8;
	$eth1_out_value = ($eth1_out_now-$eth1_out_last)/($time_now_utc-$last_datetime)*8;
	if($eth1_in_value < 0){$eth1_in_value = -1;}
	if($eth1_out_value < 0){$eth1_out_value = -1;}
}

&mysql_insert($eth0_in_value,$eth0_out_value,$eth0_in_now,$eth0_out_now,$eth1_in_value,$eth1_out_value,$eth1_in_now,$eth1_out_now);


sub mysql_insert
{
	my($net_eth0_in,$net_eth0_out,$net_eth0_inall,$net_eth0_outall,$net_eth1_in,$net_eth1_out,$net_eth1_inall,$net_eth1_outall) = @_;
	my $sqr_insert;
	if($net_eth0_in == -1 && $net_eth0_inall == -1 && $net_eth1_in == -1 && $net_eth1_inall == -1)
	{
		$sqr_insert = $dbh->prepare("insert into status (datetime,ssh_conn,telnet_conn,graph_conn,ftp_conn,db_conn,cpu,memory,swap,disk) values ('$time_now_str',$ssh_conn,$telnet_conn,$graph_conn,$ftp_conn,$db_conn,$cpu,$memory,$swap,$disk)");

	}
	elsif($net_eth0_in == -1 && $net_eth0_inall == -1 && $net_eth1_in == -1 && $net_eth1_inall != -1)
	{
		$sqr_insert = $dbh->prepare("insert into status (datetime,ssh_conn,telnet_conn,graph_conn,ftp_conn,db_conn,cpu,memory,swap,disk,net_eth1_inall,net_eth1_outall) values ('$time_now_str',$ssh_conn,$telnet_conn,$graph_conn,$ftp_conn,$db_conn,$cpu,$memory,$swap,$disk,$net_eth1_inall,$net_eth1_outall)");
	}
	elsif($net_eth0_in == -1 && $net_eth0_inall == -1 && $net_eth1_in != -1 && $net_eth1_inall != -1)
	{
		$sqr_insert = $dbh->prepare("insert into status (datetime,ssh_conn,telnet_conn,graph_conn,ftp_conn,db_conn,cpu,memory,swap,disk,net_eth1_in,net_eth1_out,net_eth1_inall,net_eth1_outall) values ('$time_now_str',$ssh_conn,$telnet_conn,$graph_conn,$ftp_conn,$db_conn,$cpu,$memory,$swap,$disk,$net_eth1_in,$net_eth1_out,$net_eth1_inall,$net_eth1_outall)");
	}
	elsif($net_eth0_in == -1 && $net_eth0_inall != -1 && $net_eth1_in == -1 && $net_eth1_inall == -1)
	{
		$sqr_insert = $dbh->prepare("insert into status (datetime,ssh_conn,telnet_conn,graph_conn,ftp_conn,db_conn,cpu,memory,swap,disk,net_eth0_inall,net_eth0_outall) values ('$time_now_str',$ssh_conn,$telnet_conn,$graph_conn,$ftp_conn,$db_conn,$cpu,$memory,$swap,$disk,$net_eth0_inall,$net_eth0_outall)");
	}
	elsif($net_eth0_in == -1 && $net_eth0_inall != -1 && $net_eth1_in == -1 && $net_eth1_inall != -1)
	{
		$sqr_insert = $dbh->prepare("insert into status (datetime,ssh_conn,telnet_conn,graph_conn,ftp_conn,db_conn,cpu,memory,swap,disk,net_eth0_inall,net_eth0_outall,net_eth1_inall,net_eth1_outall) values ('$time_now_str',$ssh_conn,$telnet_conn,$graph_conn,$ftp_conn,$db_conn,$cpu,$memory,$swap,$disk,$net_eth0_inall,$net_eth0_outall,$net_eth1_inall,$net_eth1_outall)");
	}
	elsif($net_eth0_in == -1 && $net_eth0_inall != -1 && $net_eth1_in != -1 && $net_eth1_inall != -1)
	{
		$sqr_insert = $dbh->prepare("insert into status (datetime,ssh_conn,telnet_conn,graph_conn,ftp_conn,db_conn,cpu,memory,swap,disk,net_eth0_inall,net_eth0_outall,net_eth1_in,net_eth1_out,net_eth1_inall,net_eth1_outall) values ('$time_now_str',$ssh_conn,$telnet_conn,$graph_conn,$ftp_conn,$db_conn,$cpu,$memory,$swap,$disk,$net_eth0_inall,$net_eth0_outall,$net_eth1_in,$net_eth1_out,$net_eth1_inall,$net_eth1_outall)");
	}
	elsif($net_eth0_in != -1 && $net_eth0_inall != -1 && $net_eth1_in == -1 && $net_eth1_inall == -1)
	{
		$sqr_insert = $dbh->prepare("insert into status (datetime,ssh_conn,telnet_conn,graph_conn,ftp_conn,db_conn,cpu,memory,swap,disk,net_eth0_in,net_eth0_out,net_eth0_inall,net_eth0_outall) values ('$time_now_str',$ssh_conn,$telnet_conn,$graph_conn,$ftp_conn,$db_conn,$cpu,$memory,$swap,$disk,$net_eth0_in,$net_eth0_out,$net_eth0_inall,$net_eth0_outall)");
	}
	elsif($net_eth0_in != -1 && $net_eth0_inall != -1 && $net_eth1_in == -1 && $net_eth1_inall != -1)
	{
		$sqr_insert = $dbh->prepare("insert into status (datetime,ssh_conn,telnet_conn,graph_conn,ftp_conn,db_conn,cpu,memory,swap,disk,net_eth0_in,net_eth0_out,net_eth0_inall,net_eth0_outall,net_eth1_inall,net_eth1_outall) values ('$time_now_str',$ssh_conn,$telnet_conn,$graph_conn,$ftp_conn,$db_conn,$cpu,$memory,$swap,$disk,$net_eth0_in,$net_eth0_out,$net_eth0_inall,$net_eth0_outall,$net_eth1_inall,$net_eth1_outall)");
	}
	else
	{
		$sqr_insert = $dbh->prepare("insert into status (datetime,ssh_conn,telnet_conn,graph_conn,ftp_conn,db_conn,cpu,memory,swap,disk,net_eth0_in,net_eth0_out,net_eth0_inall,net_eth0_outall,net_eth1_in,net_eth1_out,net_eth1_inall,net_eth1_outall) values ('$time_now_str',$ssh_conn,$telnet_conn,$graph_conn,$ftp_conn,$db_conn,$cpu,$memory,$swap,$disk,$net_eth0_in,$net_eth0_out,$net_eth0_inall,$net_eth0_outall,$net_eth1_in,$net_eth1_out,$net_eth1_inall,$net_eth1_outall)");
	}

	$sqr_insert->execute();
	$sqr_insert->finish();
}
=cut
sub normal_insert
{
	my($value,$type) = @_;

	my $sqr_select = $dbh->prepare("select count(*) from local_status where type = '$type'");
	$sqr_select->execute();
	my $ref_select = $sqr_select->fetchrow_hashref();
	my $type_num = $ref_select->{"count(*)"};
	$sqr_select->finish();

	if($type_num == 0)
	{
		my $sqr_insert = $dbh->prepare("insert into local_status (type,rrdfile) values ('$type','/opt/freesvr/nm/localhost_status/$type.rrd')");
		$sqr_insert->execute();
		$sqr_insert->finish();

		$sqr_select = $dbh->prepare("select enable from local_status where type = '$type'");
		$sqr_select->execute();
		$ref_select = $sqr_select->fetchrow_hashref();
		my $enable = $ref_select->{"enable"};
		$sqr_select->finish();

		if($enable != 1)
		{
			if($debug == 1)
			{
				my $sqr_update = $dbh->prepare("update local_status set enable = 1 where type = '$type'");       
				$sqr_update->execute();
				$sqr_update->finish();

				$sqr_update = $dbh->prepare("update local_status set value = $value, datetime = '$time_now_str' where type = '$type'");
				$sqr_update->execute();
				$sqr_update->finish();

				&update_rrd($value,$type);
			}
		}
		else
		{
			my $sqr_update = $dbh->prepare("update local_status set value = $value, datetime = '$time_now_str' where type = '$type'");
			$sqr_update->execute();
			$sqr_update->finish();
			&update_rrd($value,$type);
		}
	}
	else
	{
		$sqr_select = $dbh->prepare("select enable from local_status where type = '$type'");
		$sqr_select->execute();
		$ref_select = $sqr_select->fetchrow_hashref();
		my $enable = $ref_select->{"enable"};
		$sqr_select->finish();

		if($enable == 1)
		{
			my $sqr_update = $dbh->prepare("update local_status set value = $value, datetime = '$time_now_str' where type = '$type'");
			$sqr_update->execute();
			$sqr_update->finish();
			&update_rrd($value,$type);
		}
		else
		{
			my $sqr_update = $dbh->prepare("update local_status set value = null, datetime = null where type = '$type'");
			$sqr_update->execute();
			$sqr_update->finish();
		}
	}

	$sqr_select = $dbh->prepare("select mail_alarm, highvalue, lowvalue from local_status where type = '$type'");
	$sqr_select->execute();
	$ref_select = $sqr_select->fetchrow_hashref();
	my $mail_alarm = $ref_select->{"mail_alarm"};
	my $highvalue = $ref_select->{"highvalue"};
	my $lowvalue = $ref_select->{"lowvalue"};
	$sqr_select->finish();

	if((defined $mail_alarm) && ($mail_alarm == 1))
	{
		if(($value > $highvalue) || ($value < $lowvalue))
		{
#			my $sqr_insert = $dbh->prepare("insert into local_status_err(type,value,highvalue,lowvalue) values ('$type', $value, $highvalue, $lowvalue)");
#			$sqr_insert->execute();
#			$sqr_insert->finish();
		} 
	}
}

sub update_rrd
{
	my($value,$type) = @_;

	my $start_time = time;
	$start_time = (floor($start_time/300))*300;

	my $dir = "/opt/freesvr/nm/localhost_status";
	if(! -e $dir)
	{
		mkdir $dir,0755;
	}

	my $file = $dir."/$type.rrd";
	if(! -e $file)
	{
		my $create_time = $start_time - 300;
		RRDs::create($file,
				'--start', "$create_time",
				'--step', '300',
				'DS:val:GAUGE:600:U:U',
				'RRA:AVERAGE:0.5:1:576',
				'RRA:AVERAGE:0.5:12:168',
				'RRA:AVERAGE:0.5:288:28',
				);
	}

	RRDs::update(
			$file,
			'-t', 'val',
			'--', join(':', "$start_time", "$value"),
			);
}
