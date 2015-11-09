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
our %device_info;
our @decive_arr;

our $time_now_utc = time;
our($min,$hour,$mday,$mon,$year) = (localtime $time_now_utc)[1..5];
($min,$hour,$mday,$mon,$year) = (sprintf("%02d", $min),sprintf("%02d", $hour),sprintf("%02d", $mday),sprintf("%02d", $mon + 1
),$year+1900);
our $time_now_str = "$year$mon$mday$hour$min"."00";

my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});

my $utf8 = $dbh->prepare("set names utf8");
$utf8->execute();
$utf8->finish();

my $sqr_select = $dbh->prepare("select * from snmp_app_config");
$sqr_select->execute();
while(my $ref_select = $sqr_select->fetchrow_hashref())
{
	my $device_ip = $ref_select->{"device_ip"};
	my $app_name = $ref_select->{"app_name"};
	my $app_get = $ref_select->{"app_get"};
	my $url = $ref_select->{"url"};
	my $username = $ref_select->{"username"};
	my $password = $ref_select->{"password"};

	unless(defined $device_ip && $device_ip =~ /(\d{1,3}\.){3}\d{1,3}/)
	{
		next;
	}

	unless(defined $device_info{$device_ip})
	{
		my %tmp;
		$device_info{$device_ip} = \%tmp;
	}

	unless(defined $device_info{$device_ip}->{$app_name})
	{
		my @tmp;
		if($app_name eq "apache" && $app_get == 0)
		{
			my $sqr_cache_select = $dbh->prepare("select unix_timestamp(datetime),last_value from snmp_app_cache where device_ip = '$device_ip' and app_name = '$app_name' and app_type = 'traffic'");
			$sqr_cache_select->execute();
			my $ref_cache_select = $sqr_cache_select->fetchrow_hashref();
			my $last_time = $ref_cache_select->{"unix_timestamp(datetime)"};
			my $last_value = $ref_cache_select->{"last_value"};
			$sqr_cache_select->finish();

			@tmp = ($app_get,$url,$last_time,$last_value);
		}
		elsif($app_name eq "mysql")
		{
			my $sqr_cache_select = $dbh->prepare("select unix_timestamp(datetime),last_value from snmp_app_cache where device_ip = '$device_ip' and app_name = '$app_name' and app_type = 'questions'");
			$sqr_cache_select->execute();
			my $ref_cache_select = $sqr_cache_select->fetchrow_hashref();
			my $last_time = $ref_cache_select->{"unix_timestamp(datetime)"};
			my $last_value = $ref_cache_select->{"last_value"};
			$sqr_cache_select->finish();

			@tmp = ($username,$password,$last_time,$last_value);
		}
		$device_info{$device_ip}->{$app_name} = \@tmp;
	}
}
$sqr_select->finish();
my $rc = $dbh->disconnect;

if(scalar keys %device_info == 0){exit 0;}
@decive_arr = keys %device_info;
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
#               defined(my $pid = fork) or die "cannot fork:$!";
#               unless($pid){
#                   exec "/home/wuxiaolong/3_status/port_warning_group.pl",$time_now_str,$send_time;
#               }           
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
		my @temp_ips = keys %device_info;
		foreach my $key(@temp_ips)
		{
			if($device_ip ne $key)
			{
				delete $device_info{$key};
			}
		}

		my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});

		my $utf8 = $dbh->prepare("set names utf8");
		$utf8->execute();
		$utf8->finish();

		foreach my $app_name(keys %{$device_info{$device_ip}})
		{
			if($app_name eq 'apache' && $device_info{$device_ip}->{$app_name}->[0] == 0)
			{
				&apache_process($dbh,$device_ip,$app_name,$device_info{$device_ip}->{$app_name});
			}
			elsif($app_name eq 'mysql')
			{
				&mysql_process($dbh,$device_ip,$app_name,$device_info{$device_ip}->{$app_name});
			}
		}
		exit 0;
	}
	++$exist_process;
}

sub apache_process
{
	my($dbh,$device_ip,$app_name,$ref_arr) = @_;
	if($ref_arr->[0] == 0)
	{
		&apache_active($dbh,$device_ip,$app_name,$ref_arr);
	}
}

sub mysql_process
{
	my($dbh,$device_ip,$app_name,$ref_arr) = @_;
	my $username = $ref_arr->[0];
	my $password = $ref_arr->[1];
	my $last_time = $ref_arr->[2];
	my $last_value = $ref_arr->[3];
	my $mysql_status = 0;

	my $cmd;
	if(defined $password && $password ne "")
	{
		$cmd = "/opt/freesvr/sql/bin/mysqladmin -h $device_ip -u $username -p$password status 2>&1";
	}
	else
	{
		$cmd = "/opt/freesvr/sql/bin/mysqladmin -h $device_ip -u $username status 2>&1";
	}

	my $result = `$cmd`;
	foreach my $line(split /\n/,$result)
	{
		if($line =~ /Threads/i && $line =~ /Questions/i && $line =~ /Opens/i && $line =~ /Open\s*tables/i)
		{
			$mysql_status = 1;
			while($line =~ /([^:]+?\:\s*\d+)\s*/ig)
			{
				my($name,$val) = split /:/,$1;
				$name =~ s/^\s+//;
				$name =~ s/\s+$//;
				$val =~ s/^\s+//;
				$val =~ s/\s+$//;

				$name = lc($name);

				my $file_name = $name;
				$file_name =~ s/\s+/_/g;

				if($name =~ /Threads/i || $name =~ /Opens/i || $name =~ /Open\s*tables/i)
				{
					&insert_into_status($dbh,$device_ip,$app_name,$name,$val,$time_now_str);
					&update_rrd($dbh,$device_ip,$app_name,$name,'mysql_status',$file_name,$val,undef);
					print "$name,$val,\n";
				}
				elsif($name =~ /Questions/i)
				{
					if(defined $last_time && defined $last_value)
					{
						my $interval = $time_now_utc - $last_time;
						my $question_rate = ($val - $last_value) / $interval;
						&insert_into_status($dbh,$device_ip,$app_name,'questions rate',$question_rate,$time_now_str);
						&update_rrd($dbh,$device_ip,$app_name,'questions rate','mysql_status',$file_name,$question_rate,undef);

						my $sqr_update = $dbh->prepare("update snmp_app_cache set datetime = '$time_now_str', last_value = $val where device_ip = '$device_ip' and app_name = '$app_name' and app_type = 'questions'");
						$sqr_update->execute();
						$sqr_update->finish();
					}
					else
					{
						my $sqr_cache_num = $dbh->prepare("select count(*) from snmp_app_cache where device_ip = '$device_ip' and app_name = '$app_name' and app_type = 'questions'");
						$sqr_cache_num->execute();
						my $ref_cahce_num = $sqr_cache_num->fetchrow_hashref();
						my $cache_num = $ref_cahce_num->{"count(*)"};
						$sqr_cache_num->finish();

						my $cmd;
						if($cache_num == 0)
						{
							$cmd = "insert into snmp_app_cache(device_ip,datetime,app_name,app_type,last_value) values('$device_ip','$time_now_str','$app_name','questions',$val)";
						}
						else
						{
							$cmd = "update snmp_app_cache set datetime = '$time_now_str', last_value = $val where device_ip = '$device_ip' and app_name = '$app_name' and app_type = 'questions'";
						}

						my $sqr_update = $dbh->prepare("$cmd");
						$sqr_update->execute();
						$sqr_update->finish();
					}

				}
			}
		}
	}

	if($mysql_status == 0)
	{
		my $context = "无法获得主机 mysql 应用状态 $cmd 指令执行错误";
		my $sqr_insert = $dbh->prepare("insert into snmp_app_errlog (device_ip,app_name,datetime,context) values ('$device_ip','$app_name','$time_now_str','$context')");
		$sqr_insert->execute();
		$sqr_insert->finish();

		&insert_into_status($dbh,$device_ip,$app_name,'threads',-100,$time_now_str);
		&update_rrd($dbh,$device_ip,$app_name,'threads','mysql_status','threads',-100,undef);
		
		&insert_into_status($dbh,$device_ip,$app_name,'opens',-100,$time_now_str);
		&update_rrd($dbh,$device_ip,$app_name,'opens','mysql_status','opens',-100,undef);

		&insert_into_status($dbh,$device_ip,$app_name,'open tables',-100,$time_now_str);
		&update_rrd($dbh,$device_ip,$app_name,'open tables','mysql_status','open_tables',-100,undef);

		my $sqr_select = $dbh->prepare("select count(*) from snmp_app_status where device_ip = '$device_ip' and app_name = '$app_name' and app_type = 'questions rate'");
		$sqr_select->execute();
		my $ref_select = $sqr_select->fetchrow_hashref();
		my $num = $ref_select->{"count(*)"};
		$sqr_select->finish();

		if($num != 0)
		{
			&insert_into_status($dbh,$device_ip,$app_name,'questions rate',-100,$time_now_str);
			&update_rrd($dbh,$device_ip,$app_name,'questions rate','mysql_status','questions',-100,undef);
		}

		if($debug == 1)
		{
			print "$device_ip: $app_name, $context\n";
		}
	}
	return;
}

sub apache_active
{
	my($dbh,$device_ip,$app_name,$ref_arr) = @_;
	my $url = $ref_arr->[1];
	my $last_time = $ref_arr->[2];
	my $last_value = $ref_arr->[3];

	my $result = `wget $url -O /tmp/server_status_$device_ip 2>&1`;
	my $flag = 0;
	foreach my $line(split /\r*\n/,$result)
	{
		if($line =~ /200\s*OK/i)
		{
			$flag = 1;
		}
	}

	if($flag == 0)
	{
		my $context = "无法获得主机 apache 应用状态, http连接出错";
		my $sqr_insert = $dbh->prepare("insert into snmp_app_errlog (device_ip,app_name,datetime,context) values ('$device_ip','$app_name','$time_now_str','$context')");
		$sqr_insert->execute();
		$sqr_insert->finish();

		&insert_into_status($dbh,$device_ip,$app_name,'cpu',-100,$time_now_str);
		&update_rrd($dbh,$device_ip,$app_name,'cpu','apache_status','cpu',-100,undef);

		&insert_into_status($dbh,$device_ip,$app_name,'request rate',-100,$time_now_str);
		&update_rrd($dbh,$device_ip,$app_name,'request rate','apache_status','request_rate',-100,undef);

		my $sqr_select = $dbh->prepare("select count(*) from snmp_app_status where device_ip = '$device_ip' and app_name = '$app_name' and app_type = 'traffic rate'");
		$sqr_select->execute();
		my $ref_select = $sqr_select->fetchrow_hashref();
		my $num = $ref_select->{"count(*)"};
		$sqr_select->finish();

		if($num != 0)
		{
			&insert_into_status($dbh,$device_ip,$app_name,'traffic rate',-100,$time_now_str);
			&update_rrd($dbh,$device_ip,$app_name,'traffic rate','apache_status','traffic_rate',-100,undef);
		}

		if($debug == 1)
		{
			print "$device_ip: $app_name, $context\n";
		}
		unlink "/tmp/server_status_$device_ip";
		return;
	}

	&read_html_file($dbh,$device_ip,$app_name,$last_time,$last_value);
	unlink "/tmp/server_status_$device_ip";
}

sub read_html_file
{
	my($dbh,$device_ip,$app_name,$last_time,$last_value) = @_;
	my $total_traffic;
	my $cpu;
	my $request_rate;
	my $traffic_rate = undef;

	open(my $fd_fr,"</tmp/server_status_$device_ip");
	while(my $line = <$fd_fr>)
	{
		chomp $line;
		if($line =~ /Total\s*Traffic\s*:\s*([\w\s\.]+)/i)
		{
			$total_traffic = $1;
			if($total_traffic =~ /([\d\.]*)\s*GB/i)
			{
				$total_traffic = $1;
				$total_traffic = floor($total_traffic * 1024 * 1024 * 1024 * 8);
			}
			elsif($total_traffic =~ /([\d\.]*)\s*MB/i)
			{
				$total_traffic = $1;
				$total_traffic = floor($total_traffic * 1024 * 1024 * 8);
			}
			elsif($total_traffic =~ /([\d\.]*)\s*KB/i)
			{ 
				$total_traffic = $1;
				$total_traffic = floor($total_traffic * 1024 * 8);
			}
			elsif($total_traffic =~ /([\d\.]*)\s*B/i)
			{ 
				$total_traffic = $1;
				$total_traffic = floor($total_traffic * 8);
			}
		}
		if($line =~ /([\d\.]*)\%\s*CPU\s*load/i)
		{
			$cpu = sprintf("%.6f",$1);
		}
		if($line =~ /([\d\.]*)\s*requests\/sec/i)
		{
			$request_rate = sprintf("%.6f",$1);
		}
	}
	close $fd_fr;

	&insert_into_status($dbh,$device_ip,$app_name,'cpu',$cpu,$time_now_str);
	&update_rrd($dbh,$device_ip,$app_name,'cpu','apache_status','cpu',$cpu,undef);

	&insert_into_status($dbh,$device_ip,$app_name,'request rate',$request_rate,$time_now_str);
	&update_rrd($dbh,$device_ip,$app_name,'request rate','apache_status','request_rate',$request_rate,undef);

	if(defined $last_time && defined $last_value)
	{
		my $interval = $time_now_utc - $last_time;
		$traffic_rate = ($total_traffic - $last_value) / $interval;
		&insert_into_status($dbh,$device_ip,$app_name,'traffic rate',$traffic_rate,$time_now_str);
		&update_rrd($dbh,$device_ip,$app_name,'traffic rate','apache_status','traffic_rate',$traffic_rate,undef);

		my $sqr_update = $dbh->prepare("update snmp_app_cache set datetime = '$time_now_str', last_value = $total_traffic where device_ip = '$device_ip' and app_name = '$app_name' and app_type = 'traffic'");
		$sqr_update->execute();
		$sqr_update->finish();
	}
	else
	{
		my $sqr_cache_num = $dbh->prepare("select count(*) from snmp_app_cache where device_ip = '$device_ip' and app_name = '$app_name' and app_type = 'traffic'");
		$sqr_cache_num->execute();
		my $ref_cahce_num = $sqr_cache_num->fetchrow_hashref();
		my $cache_num = $ref_cahce_num->{"count(*)"};
		$sqr_cache_num->finish();

		my $cmd;
		if($cache_num == 0)
		{
			$cmd = "insert into snmp_app_cache(device_ip,datetime,app_name,app_type,last_value) values('$device_ip','$time_now_str','$app_name','traffic',$total_traffic)";
		}
		else
		{
			$cmd = "update snmp_app_cache set datetime = '$time_now_str', last_value = $total_traffic where device_ip = '$device_ip' and app_name = '$app_name' and app_type = 'traffic'";
		}

		my $sqr_update = $dbh->prepare("$cmd");
		$sqr_update->execute();
		$sqr_update->finish();
	}
}

sub insert_into_status
{
	my($dbh,$device_ip,$app_name,$app_type,$value,$cur_time) = @_;

	my $sqr_select = $dbh->prepare("select count(*) from snmp_app_status where device_ip = '$device_ip' and app_name = '$app_name' and app_type = '$app_type'");
	$sqr_select->execute();
	my $ref_select = $sqr_select->fetchrow_hashref();
	my $device_num = $ref_select->{"count(*)"};
	$sqr_select->finish();

	if($device_num == 0)
	{
		my $sqr_insert = $dbh->prepare("insert into snmp_app_status(device_ip,app_name,app_type) values('$device_ip','$app_name','$app_type')");
		$sqr_insert->execute();
		$sqr_insert->finish();

		$sqr_select = $dbh->prepare("select enable from snmp_app_status where device_ip = '$device_ip' and app_name = '$app_name' and app_type = '$app_type'");
		$sqr_select->execute();
		$ref_select = $sqr_select->fetchrow_hashref();
		my $enable = $ref_select->{"enable"};
		$sqr_select->finish();

		if($enable != 1)
		{
			if($debug == 1)
			{
				my $sqr_update = $dbh->prepare("update snmp_app_status set enable = 1 where device_ip = '$device_ip' and app_name = '$app_name' and app_type = '$app_type'");
				$sqr_update->execute();
				$sqr_update->finish();

				$sqr_update = $dbh->prepare("update snmp_app_status set value = $value, datetime = '$cur_time' where device_ip = '$device_ip' and app_name = '$app_name' and app_type = '$app_type'");
				$sqr_update->execute();
				$sqr_update->finish();
			}
			else
			{
				my $cache_name = $app_type;
				$cache_name = s/\s+rate//g;
				my $sqr_delete = $dbh->prepare("delete from snmp_app_cache where device_ip = '$device_ip' and app_name = '$app_name' and app_type = '$cache_name'");
				$sqr_delete->execute();
				$sqr_delete->finish();
			}
		}
		else
		{
			my $sqr_update = $dbh->prepare("update snmp_app_status set value = $value, datetime = '$cur_time' where device_ip = '$device_ip' and app_name = '$app_name' and app_type = '$app_type'");
			$sqr_update->execute();
			$sqr_update->finish();
		}
	}
	else
	{
		my $sqr_select = $dbh->prepare("select enable from snmp_app_status where device_ip = '$device_ip' and app_name = '$app_name' and app_type = '$app_type'");
		$sqr_select->execute();
		$ref_select = $sqr_select->fetchrow_hashref();
		my $enable = $ref_select->{"enable"};
		$sqr_select->finish();

		if($enable == 1)
		{
			my $sqr_update = $dbh->prepare("update snmp_app_status set value = $value, datetime = '$cur_time' where device_ip = '$device_ip' and app_name = '$app_name' and app_type = '$app_type'");
			$sqr_update->execute();
			$sqr_update->finish();
		}
		else
		{
			my $sqr_update = $dbh->prepare("update snmp_app_status set value = null, datetime = null where device_ip = '$device_ip' and app_name = '$app_name' and app_type = '$app_type'");
			$sqr_update->execute();
			$sqr_update->finish();

			my $cache_name = $app_type;
			$cache_name = s/\s+rate//g;
			my $sqr_delete = $dbh->prepare("delete from snmp_app_cache where device_ip = '$device_ip' and app_name = '$app_name' and app_type = '$cache_name'");
			$sqr_delete->execute();
			$sqr_delete->finish();
		}

	}
}

sub update_rrd
{           
	my($dbh,$device_ip,$app_name,$app_type,$dir_name,$file_name,$val,$start_time) = @_;

	if(!defined $val || $val < 0)
	{
		$val = 'U';
	}

	my $enable;
	my $rrdfile;

	my $sqr_select = $dbh->prepare("select enable,rrdfile from snmp_app_status where device_ip = '$device_ip' and app_name = '$app_name' and app_type = '$app_type'");
	$sqr_select->execute();
	my $ref_select = $sqr_select->fetchrow_hashref();
	$enable = $ref_select->{"enable"};
	$rrdfile = $ref_select->{"rrdfile"};
	$sqr_select->finish();

	unless(defined $start_time)
	{
		$start_time = time;
	}

	$start_time = (floor($start_time/300))*300;

	my $dir = "/opt/freesvr/nm/$device_ip";
	if(! -e $dir)
	{
		mkdir $dir,0755;
	}   

	$dir = "$dir/$dir_name";
	if(! -e $dir)
	{
		mkdir $dir,0755;
	}   

	my $file = $dir."/$file_name.rrd";

	unless(defined $enable && $enable == 1) 
	{
		unless(defined $rrdfile && -e $rrdfile && $rrdfile eq $file)
		{
			if(defined $rrdfile && -e $rrdfile)
			{
				unlink $rrdfile;
				my $sqr_update = $dbh->prepare("update snmp_app_status set rrdfile = null where device_ip = '$device_ip' and app_name = '$app_name' and app_type = '$app_type'");
				$sqr_update->execute();
				$sqr_update->finish();
				return;
			}
		}
	}

	if(! -e $file)
	{
		my $create_time = $start_time - 300;
		RRDs::create($file,
				'--start', "$create_time",
				'--step', '300',
				'DS:val:GAUGE:600:U:U',
				'RRA:AVERAGE:0.5:1:576',
				'RRA:AVERAGE:0.5:12:192',
				'RRA:AVERAGE:0.5:288:32',
				'RRA:MAX:0.5:1:576',
				'RRA:MAX:0.5:12:192',
				'RRA:MAX:0.5:288:32',
				'RRA:MIN:0.5:1:576',
				'RRA:MIN:0.5:12:192',
				'RRA:MIN:0.5:288:32',
				);
	}
	
	unless(defined $rrdfile && $rrdfile eq $file)
	{
		my $sqr_update = $dbh->prepare("update snmp_app_status set rrdfile = '$file' where device_ip = '$device_ip' and app_name = '$app_name' and app_type = '$app_type'");
		$sqr_update->execute();
		$sqr_update->finish();

		if(defined $rrdfile && -e $rrdfile)
		{
			unlink $rrdfile;
		}
	}   

	RRDs::update(
			$file,
			'-t', 'val',
			'--', join(':', "$start_time", "$val"),
			);
}
