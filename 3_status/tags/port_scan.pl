#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use DBD::mysql;
use RRDs;
use POSIX qw/ceil floor/;

our $debug = 1;
our $max_process_num = 2;
our $exist_process = 0;
our %ip_port;
our @decive_arr;

our $time_now_utc = time;
our($min,$hour,$mday,$mon,$year) = (localtime $time_now_utc)[1..5];
($min,$hour,$mday,$mon,$year) = (sprintf("%02d", $min),sprintf("%02d", $hour),sprintf("%02d", $mday),sprintf("%02d", $mon + 1),$year+1900);
our $time_now_str = "$year$mon$mday$hour$min"."00";
our $send_time = "$year-$mon-$mday $hour:$min";

my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});

my $utf8 = $dbh->prepare("set names utf8");
$utf8->execute();
$utf8->finish();

my $sqr_select = $dbh->prepare("select device_ip,port_monitor,port_monitor_time,monitor,snmpkey from servers where port_monitor is not null");
$sqr_select->execute();
while(my $ref_select = $sqr_select->fetchrow_hashref())
{
	my $device_ip = $ref_select->{"device_ip"};
	my $port_str = $ref_select->{"port_monitor"};
	my $timeout = $ref_select->{"port_monitor_time"};
	my $monitor = $ref_select->{"monitor"};
	my $snmpkey = $ref_select->{"snmpkey"};

	if($monitor != 1 && $monitor !=2 && $snmpkey ne "")
	{
		&get_sys_runtime($dbh,$device_ip,$snmpkey);
	}

	unless(defined $timeout)
	{
		my $context = "$device_ip 未定义超时阀值";
		if($debug == 1)
		{
			print $context,"\n";
		}

		my $sqr_insert = $dbh->prepare("insert into tcp_port_alarm (datetime,ip,context) values ('$time_now_str','$device_ip','$context')");
		$sqr_insert->execute();
		$sqr_insert->finish();
	}

	my @tmp_ports = split /,/,$port_str;
	if(scalar @tmp_ports == 0){next;}

	unless(exists $ip_port{$device_ip})
	{
		my %ports;
		$ip_port{$device_ip} = \%ports;
	}

	foreach(@tmp_ports)
	{
		unless($_ =~ /\d+/){next;}
		my @times = ($timeout,undef);
		$ip_port{$device_ip}->{$_} = \@times;
	}
}
$sqr_select->finish();
my $rc = $dbh->disconnect;

if(scalar keys %ip_port == 0){exit 0;}
@decive_arr = keys %ip_port;
if($max_process_num > scalar @decive_arr){$max_process_num = scalar @decive_arr;}

while(1)
{
	if($exist_process < $max_process_num)
	{
		&fork_process();
	}
	else
	{
		while(wait())
		{
			--$exist_process;
			&fork_process();
			if($exist_process == 0)
			{
#				defined(my $pid = fork) or die "cannot fork:$!";
#				unless($pid){
#					exec "/home/wuxiaolong/3_status/port_warning_group.pl",$time_now_str,$send_time;
#				}           
				exit;
			}
		}
	}
}

sub fork_process
{
	my $device_ip = shift @decive_arr;
	unless(defined $device_ip){return;}
	my $pid = fork();
	if (!defined($pid))
	{
		print "Error in fork: $!";
		exit 1;
	}

	if ($pid == 0)
	{
		my @temp_ips = keys %ip_port;
		foreach my $key(@temp_ips)
		{
			if($device_ip ne $key)
			{
				delete $ip_port{$key};
			}
		}

		my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});

		my $utf8 = $dbh->prepare("set names utf8");
		$utf8->execute();
		$utf8->finish();

		&port_scan($dbh,$device_ip);
		exit 0;
	}
	++$exist_process;
}

sub get_sys_runtime
{
    my($dbh,$device_ip,$snmpkey) = @_;
    my $result = `snmpwalk -v 2c -c $snmpkey $device_ip DISMAN-EVENT-MIB::sysUpTimeInstance 2>&1`;
    foreach my $line(split /\r*\n/,$result)
    {
        if($line =~ /sysUpTimeInstance/i && $line =~ /Timeticks\s*:\s*\((\d+)\)/i)
        {
            my $sys_start_time = $1;
            
            my $sqr_select = $dbh->prepare("select count(*) from servers where device_ip = '$device_ip' and snmpkey = '$snmpkey'");      
            $sqr_select->execute();
            my $ref_select = $sqr_select->fetchrow_hashref();
            my $ip_num = $ref_select->{"count(*)"};
            $sqr_select->finish();
            
            if($ip_num == 0)
            {
                my $sqr_insert = $dbh->prepare("insert into servers (device_ip,snmpkey,snmptime) values ('$device_ip','$snmpkey',$sys_start_time)");
                $sqr_insert->execute();
                $sqr_insert->finish();
            }   
            else
            {
                my $sqr_update = $dbh->prepare("update servers set snmptime = $sys_start_time where device_ip = '$device_ip' and snmpkey = '$snmpkey'");
                $sqr_update->execute();
                $sqr_update->finish();
            }   
        }   
    }
}

sub port_scan
{
	my($dbh,$device_ip) = @_;

	my $flag = 0;
	my $nmap_str = "nmap -n -sT -p ".join(",",keys %{$ip_port{$device_ip}})." $device_ip";
	if($debug == 1)
	{
		print $nmap_str,"\n";
	}

	my $nmap = `$nmap_str`;

	my @lines = split /\n/,$nmap;
	foreach my $line(@lines)
	{
		if($line =~ /MAC\s*Address/i) {next;}
		if($flag == 1 && $line =~ /^$/) {last;}

		if($flag == 1)
		{
			my($port,$status) = (split /\s+/,$line)[0,1];
			$port = (split /\//,$port)[0];

			unless($status eq "open")
			{
				if($debug == 1)
				{
					print "$device_ip,$port  :  status: $status\n";
				}

				&insert_val($dbh,$device_ip,$port,undef,"端口 $port 未开放");
				delete $ip_port{$device_ip}->{$port};
			}
		}
		elsif($line =~ /PORT\s*STATE\s*SERVICE/i)
		{
			$flag = 1;
		}
	}

	if($flag == 0)
	{
		foreach my $port(keys %{$ip_port{$device_ip}})
		{
			&insert_val($dbh,$device_ip,$port,undef,"端口 $port 未扫描到");
		}
		return;
	}

	foreach my $port(keys %{$ip_port{$device_ip}})
	{
		my $result = `tcptraceroute -p $port -f 29 $device_ip | tail -n 1`;
		if($result =~ /ms/i)
		{
			$result =~ s/(\d+)\s*ms/$1ms/g;
		}
		my @time = (split /\s+/,$result)[-3,-2,-1];

		my $min_time = 0;
		foreach(@time)
		{
			if($_ =~ /ms/i && $_ =~ /(\d+\.\d+)/i)
			{
				if($min_time == 0){$min_time = $1;}
				elsif($1<$min_time){$min_time = $1;}
			}
		}

		$ip_port{$device_ip}->{$port}->[1] = $min_time;

		if($min_time == 0)
		{
			&insert_val($dbh,$device_ip,$port,undef,"端口 $port tcptraceroute 不可达");
		}
		elsif($min_time < $ip_port{$device_ip}->{$port}->[0])
		{
			&insert_val($dbh,$device_ip,$port,$min_time,undef);
		}
		else
		{
			&insert_val($dbh,$device_ip,$port,$min_time,"端口 $port tcptraceroute 超过阀值");
		}
	}
}

sub insert_val
{
	my($dbh,$device_ip,$port,$time,$context) = @_;
	my $sqr_select_port = $dbh->prepare("select count(*) from tcp_port_value where ip = '$device_ip' and tcpport = $port");
	$sqr_select_port->execute();
	my $ref_select_port = $sqr_select_port->fetchrow_hashref();
	my $port_num = $ref_select_port->{"count(*)"};
	$sqr_select_port->finish();

	if(defined $time)
	{
		if($port_num == 0)
		{
			my $sqr_insert = $dbh->prepare("insert into tcp_port_value (datetime,ip,tcpport,time) values ('$time_now_str','$device_ip',$port,$time)");
			$sqr_insert->execute();
			$sqr_insert->finish();
		}
		else
		{
			my $sqr_update = $dbh->prepare("update tcp_port_value set datetime = '$time_now_str', time = $time where ip = '$device_ip' and tcpport = $port");
			$sqr_update->execute();
			$sqr_update->finish();
		}

		&update_rrd($dbh,$device_ip,$port,$time);
	}
	else
	{
		if($port_num == 0)
		{
			my $sqr_insert = $dbh->prepare("insert into tcp_port_value (datetime,ip,tcpport) values ('$time_now_str','$device_ip',$port)");
			$sqr_insert->execute();
			$sqr_insert->finish();
		}
		else
		{
			my $sqr_update = $dbh->prepare("update tcp_port_value set datetime = '$time_now_str', time = null where ip = '$device_ip' and tcpport = $port");
			$sqr_update->execute();
			$sqr_update->finish();
		}
	}

	if(defined $context)
	{
		my $sqr_insert = $dbh->prepare("insert into tcp_port_alarm (datetime,ip,tcpport,context) values ('$time_now_str','$device_ip',$port,'$context')");
		$sqr_insert->execute();
		$sqr_insert->finish();

		if($debug == 1)
		{
			print "$device_ip $port: $context\n";
		}
	}
}

sub update_rrd
{
	my($dbh,$device_ip,$port,$time) = @_;

	my $start_time = time;
	$start_time = (floor($start_time/300))*300;

	my $dir = "/opt/freesvr/nm/$device_ip/port_scan_time";
	if(! -e $dir)
	{
		mkdir $dir,0755;
	}   

	my $file = $dir."/$port.rrd";
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

		my $sqr_select_rrd = $dbh->prepare("select rrdfile from tcp_port_value where ip = '$device_ip' and tcpport = $port");
		$sqr_select_rrd->execute();
		my $ref_select_rrd = $sqr_select_rrd->fetchrow_hashref();
		my $rrdfile_name = $ref_select_rrd->{"rrdfile"};
		$sqr_select_rrd->finish();

		if(!defined $rrdfile_name || $rrdfile_name ne $file)
		{
			if(defined $rrdfile_name){unlink $rrdfile_name;}
			my $sqr_update = $dbh->prepare("update tcp_port_value set rrdfile = '$file' where ip = '$device_ip' and tcpport = $port");
			$sqr_update->execute();
			$sqr_update->finish();
		}
	}

	RRDs::update(
			$file,
			'-t', 'val',
			'--', join(':', "$start_time", "$time"),
			);
}
