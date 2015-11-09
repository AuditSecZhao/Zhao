#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use DBD::mysql;
use RRDs;
use POSIX qw/ceil floor/;

our $debug = 1;
our $max_process_num = 5;           
our $exist_process = 0;  
our @device_info_ips;

our %device_info;
our %cache_info;
our %cur_info;

our $time_now_utc = time;
my($min,$hour,$mday,$mon,$year) = (localtime $time_now_utc)[1..5];
($min,$hour,$mday,$mon,$year) = (sprintf("%02d", $min),sprintf("%02d", $hour),sprintf("%02d", $mday),sprintf("%02d", $mon + 1),$year+1900);
our $time_now_str = "$year$mon$mday$hour$min"."00";

my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});
            
my $utf8 = $dbh->prepare("set names utf8");
$utf8->execute();
$utf8->finish();

my $sqr_select = $dbh->prepare("select device_ip from snmp_interface group by device_ip");
$sqr_select->execute();
while(my $ref_select = $sqr_select->fetchrow_hashref())
{
	my $device_ip = $ref_select->{"device_ip"};
	unless(exists $device_info{$device_ip})
	{
		my $sqr_select_key = $dbh->prepare("select snmpkey from servers where monitor=1 and snmpnet=1 and device_ip='$device_ip'");
		$sqr_select_key->execute();
		my $ref_select_key = $sqr_select_key->fetchrow_hashref();
		my $snmp_key = $ref_select_key->{"snmpkey"};
		$sqr_select_key->finish();
		unless(defined $snmp_key)
		{
			&insert_log($dbh,$device_ip,$time_now_str,undef,"$device_ip servers 没有配置");
			&update_nan($dbh,$device_ip,undef);
			next;
		}

		my %tmp_hash;
		my @tmp_arr = ($snmp_key,undef,\%tmp_hash);
		$device_info{$device_ip} = \@tmp_arr;
	}
}
$sqr_select->finish();
my $rc = $dbh->disconnect;

if(scalar keys %device_info == 0){exit 0;}
@device_info_ips = keys %device_info;
if($max_process_num > scalar @device_info_ips){$max_process_num = scalar @device_info_ips;}

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
				exit;
			}
		}
	}
}

sub fork_process
{
	my $device_ip = shift @device_info_ips;
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

		&create_index_hash($dbh,$device_ip);
		&create_cache_hash($dbh,$device_ip);
		&create_cur_hash($dbh,$device_ip,$device_info{$device_ip}->[0]);
		&cal_result($dbh,$device_ip);
		&write_info($dbh,$device_ip);
		exit 0;
	}

	++$exist_process;
}

sub create_index_hash
{
	my ($dbh,$device_ip) = @_;

	my $sqr_select_first = $dbh->prepare("select count(*) from snmp_interface_cache where device_ip = '$device_ip'");
	$sqr_select_first->execute();
	my $ref_select_first = $sqr_select_first->fetchrow_hashref();
	my $is_first = $ref_select_first->{"count(*)"} == 0 ? 1 : 0;
	$sqr_select_first->finish();
	$device_info{$device_ip}->[1] = $is_first;

	my $sqr_select_index = $dbh->prepare("select enable,port_index,normal_status,traffic_in_highvalue,traffic_in_lowvalue,traffic_out_highvalue,traffic_out_lowvalue,packet_in_highvalue,packet_in_lowvalue,packet_out_highvalue,packet_out_lowvalue,err_packet_in_highvalue,err_packet_in_lowvalue,err_packet_out_highvalue,err_packet_out_lowvalue,traffic_RRD,packet_RRD,err_packet_RRD from snmp_interface where device_ip = '$device_ip'");
	$sqr_select_index->execute();
	while(my $ref_select_index = $sqr_select_index->fetchrow_hashref())
	{
		my $enable = $ref_select_index->{"enable"};
		my $port_index = $ref_select_index->{"port_index"};
		if($enable != 1)
		{
			&update_nan($dbh,$device_ip,$port_index);
			next;
		}

		my $normal_status = $ref_select_index->{"normal_status"};
		my $traffic_in_highvalue = $ref_select_index->{"traffic_in_highvalue"};
		my $traffic_in_lowvalue = $ref_select_index->{"traffic_in_lowvalue"};
		my $traffic_out_highvalue = $ref_select_index->{"traffic_out_highvalue"};
		my $traffic_out_lowvalue = $ref_select_index->{"traffic_out_lowvalue"};
		my $packet_in_highvalue = $ref_select_index->{"packet_in_highvalue"};
		my $packet_in_lowvalue = $ref_select_index->{"packet_in_lowvalue"};
		my $packet_out_highvalue = $ref_select_index->{"packet_out_highvalue"};
		my $packet_out_lowvalue = $ref_select_index->{"packet_out_lowvalue"};
		my $err_packet_in_highvalue = $ref_select_index->{"err_packet_in_highvalue"};
		my $err_packet_in_lowvalue = $ref_select_index->{"err_packet_in_lowvalue"};
		my $err_packet_out_highvalue = $ref_select_index->{"err_packet_out_highvalue"};
		my $err_packet_out_lowvalue = $ref_select_index->{"err_packet_out_lowvalue"};
		my $traffic_RRD = $ref_select_index->{"traffic_RRD"};
		my $packet_RRD = $ref_select_index->{"packet_RRD"};
		my $err_packet_RRD = $ref_select_index->{"err_packet_RRD"};

		my @traffic_in_thold = ($traffic_in_highvalue,$traffic_in_lowvalue);
		my @traffic_out_thold = ($traffic_out_highvalue,$traffic_out_lowvalue);
		my @packet_in_thold = ($packet_in_highvalue,$packet_in_lowvalue);
		my @packet_out_thold = ($packet_out_highvalue,$packet_out_lowvalue);
		my @err_packet_in_thold = ($err_packet_in_highvalue,$err_packet_in_lowvalue);
		my @err_packet_out_thold = ($err_packet_out_highvalue,$err_packet_out_lowvalue);

		my @tmp_thold = ($normal_status,\@traffic_in_thold,\@traffic_out_thold,\@packet_in_thold,\@packet_out_thold,\@err_packet_in_thold,\@err_packet_out_thold);
		my @cur_val = (undef,undef,undef,undef,undef,undef,undef);

		my @index_info = ($traffic_RRD,$packet_RRD,$err_packet_RRD,\@tmp_thold,\@cur_val);

		unless(exists $device_info{$device_ip}->[2]->{$port_index})
		{
			$device_info{$device_ip}->[2]->{$port_index} = \@index_info;
		}

	}
	$sqr_select_index->finish();
}

sub create_cache_hash
{
	my ($dbh,$device_ip) = @_;
	my $sqr_select_index = $dbh->prepare("select port_index,unix_timestamp(datetime),traffic_in,traffic_out,packet_in,packet_out,err_packet_in,err_packet_out from snmp_interface_cache where device_ip = '$device_ip'");
	$sqr_select_index->execute();
	while(my $ref_select_index = $sqr_select_index->fetchrow_hashref())
	{
		my $port_index = $ref_select_index->{"port_index"};
		my $last_time = $ref_select_index->{"unix_timestamp(datetime)"};
		my $traffic_in = $ref_select_index->{"traffic_in"};
		my $traffic_out = $ref_select_index->{"traffic_out"};
		my $packet_in = $ref_select_index->{"packet_in"};
		my $packet_out = $ref_select_index->{"packet_out"};
		my $err_packet_in = $ref_select_index->{"err_packet_in"};
		my $err_packet_out = $ref_select_index->{"err_packet_out"};

		my @last_index_val = ($last_time,$traffic_in,$traffic_out,$packet_in,$packet_out,$err_packet_in,$err_packet_out);

		unless(exists $cache_info{$device_ip})
		{
			my %tmp_hash;
			$cache_info{$device_ip} = \%tmp_hash;
		}

		unless(exists $cache_info{$device_ip}->{$port_index})
		{
			$cache_info{$device_ip}->{$port_index} = \@last_index_val;
		}
	}
	$sqr_select_index->finish();
}

sub create_cur_hash
{
	my ($dbh,$device_ip,$snmp_key) = @_;
	my %snmp_argv = (
			'ifOperStatus' => 0,
			'ifHCInOctets' => 1,
			'ifHCOutOctets' => 2,
			'ifHCInUcastPkts' => 3,
			'ifHCOutUcastPkts' => 4,
			'ifInErrors' => 5,
			'ifOutErrors' => 6
			);

	unless(exists $cur_info{$device_ip})
	{
		my %cur_val_hash;
		my $time_now = time;
		my @tmp_arr = ($time_now,\%cur_val_hash);
		$cur_info{$device_ip} = \@tmp_arr;
	
		foreach my $key(keys %snmp_argv)
		{
			&cal_val($dbh,$device_ip,$snmp_key,$key,$snmp_argv{$key});
		}
	}
}

sub cal_val
{
	my($dbh,$device_ip,$snmp_key,$snmp_arg,$pos) = @_;

	my $cmd = "snmpwalk -v 2c -c $snmp_key $device_ip $snmp_arg";
	my $index;
	my $val;

	my $context = `$cmd`;
	foreach my $line(split /\n/,$context)
	{
		if($line =~ /Timeout.*No Response from/i)
		{
			my $time_now = time;
			&insert_log($dbh,$device_ip,$time_now_str,undef,"$device_ip 没有响应");
			&update_nan($dbh,$device_ip,undef);
			exit 0;
		}

		if($pos == 0 && $line =~ /ifOperStatus\D*(\d+).*INTEGER\s*:*\s*(.+)$/i)
		{
			$index = $1;
			$val = $2;
			$val =~ s/\(.*\)//;
		}
		elsif($line =~ /$snmp_arg\D*(\d+).*Counter\d+\s*:*\s*(\d+)$/i)
		{
			$index = $1;
			$val = $2;
		}

		unless(exists $cur_info{$device_ip}->[1]->{$index})
		{
			my @tmp_arr = (undef,undef,undef,undef,undef,undef,undef);
			$cur_info{$device_ip}->[1]->{$index} = \@tmp_arr;
		}

		unless(defined $cur_info{$device_ip}->[1]->{$index}->[$pos])
		{
			$cur_info{$device_ip}->[1]->{$index}->[$pos] = $val;
		}
	}
}

sub cal_result
{
	my($dbh,$device_ip) = @_;

	my @tmp_column_name = (undef,"traffic_in","traffic_out","packet_in","packet_out","err_packet_in","err_packet_out");

	my $time_now = $cur_info{$device_ip}->[0];

	my @tmp_port_arr;
	foreach my $port(keys %{$device_info{$device_ip}->[2]})
	{
		unless(exists $cur_info{$device_ip}->[1]->{$port})
		{
			push @tmp_port_arr,$port;
			next;
		}

#		$device_info{$device_ip}->[2]->{$port}->[5] = $time_now;
	}

	foreach my $port(@tmp_port_arr)
	{
		&update_nan($dbh,$device_ip,$port);
		delete $device_info{$device_ip}->[2]->{$port};
	}

	foreach my $port(keys %{$cur_info{$device_ip}->[1]})
	{
		my $insert_bef;
		my $insert_aft;
		my $update_cmd;
		my $insert_flag;

		unless(exists $device_info{$device_ip}->[2]->{$port}){next;}

		if(defined $cur_info{$device_ip}->[1]->{$port}->[0])
		{
			$device_info{$device_ip}->[2]->{$port}->[4]->[0] = $cur_info{$device_ip}->[1]->{$port}->[0];
		}

		foreach (1..6)
		{
			if(defined $cur_info{$device_ip}->[1]->{$port}->[$_])
			{
				unless(defined $insert_flag)
				{
					my $sqr_select_cache = $dbh->prepare("select count(*) from snmp_interface_cache where device_ip = '$device_ip' and port_index = '$port'");
					$sqr_select_cache->execute();
					my $ref_select_cache = $sqr_select_cache->fetchrow_hashref();
					my $num = $ref_select_cache->{"count(*)"};
					$sqr_select_cache->finish();

					if($num == 0)
					{
						$insert_flag = 1;
						$insert_bef = "insert into snmp_interface_cache (device_ip,datetime,port_index";
						$insert_aft = " values ('$device_ip',FROM_UNIXTIME($time_now),$port";
					}
					else
					{
						$insert_flag = 0;
						$update_cmd = "update snmp_interface_cache set datetime = FROM_UNIXTIME($time_now)";
					}
				}

				if($insert_flag == 1)
				{
					$insert_bef .= ",$tmp_column_name[$_]";
					$insert_aft .= ",$cur_info{$device_ip}->[1]->{$port}->[$_]";
				}
				else
				{
					$update_cmd .= ",$tmp_column_name[$_] = $cur_info{$device_ip}->[1]->{$port}->[$_]";
				}

				if(defined $cache_info{$device_ip}->{$port} && defined $cache_info{$device_ip}->{$port}->[$_])
				{
					my $interval = $time_now - $cache_info{$device_ip}->{$port}->[0];
					$device_info{$device_ip}->[2]->{$port}->[4]->[$_] = $cur_info{$device_ip}->[1]->{$port}->[$_]-$cache_info{$device_ip}->{$port}->[$_];
					$device_info{$device_ip}->[2]->{$port}->[4]->[$_] /= $interval;
					$device_info{$device_ip}->[2]->{$port}->[4]->[$_] = floor($device_info{$device_ip}->[2]->{$port}->[4]->[$_] * 100) / 100;

#					if($device_info{$device_ip}->[2]->{$port}->[4]->[$_] < 0){}			# <0 备用
				}
			}
		}

		if(defined $insert_flag)
		{
			if($insert_flag == 1)
			{
				$insert_bef .= ")";
				$insert_aft .= ")";
				my $sqr_insert_cache = $dbh->prepare("$insert_bef $insert_aft");
				$sqr_insert_cache->execute();
				$sqr_insert_cache->finish();
			}
			elsif($insert_flag == 0)
			{
				$update_cmd .= " where device_ip = '$device_ip' and port_index = $port";
				my $sqr_update_cache = $dbh->prepare("$update_cmd");
				$sqr_update_cache->execute();
				$sqr_update_cache->finish();
			}
		}
	}
}

sub write_info
{
	my ($dbh,$device_ip) = @_;

	foreach my $port(keys %{$device_info{$device_ip}->[2]})
	{
#更新 snmp_interface 表
		my $update_cmd = "update snmp_interface set ";
		if(defined $device_info{$device_ip}->[2]->{$port}->[4]->[0])
		{
			$update_cmd .= "cur_status = '$device_info{$device_ip}->[2]->{$port}->[4]->[0]',";
		}
		else
		{
			$update_cmd .= "cur_status = null,";
		}

		if(defined $device_info{$device_ip}->[2]->{$port}->[4]->[1])
		{
			$update_cmd .= "traffic_in = $device_info{$device_ip}->[2]->{$port}->[4]->[1],";
		}
		else
		{
			$update_cmd .= "traffic_in = null,";
		}

		if(defined $device_info{$device_ip}->[2]->{$port}->[4]->[2])
		{
			$update_cmd .= "traffic_out = $device_info{$device_ip}->[2]->{$port}->[4]->[2],";
		}
		else
		{
			$update_cmd .= "traffic_out = null,";
		}

		if(defined $device_info{$device_ip}->[2]->{$port}->[4]->[3])
		{
			$update_cmd .= "packet_in = $device_info{$device_ip}->[2]->{$port}->[4]->[3],";
		}
		else
		{
			$update_cmd .= "packet_in = null,";
		}

		if(defined $device_info{$device_ip}->[2]->{$port}->[4]->[4])
		{
			$update_cmd .= "packet_out = $device_info{$device_ip}->[2]->{$port}->[4]->[4],";
		}
		else
		{
			$update_cmd .= "packet_out = null,";
		}

		if(defined $device_info{$device_ip}->[2]->{$port}->[4]->[5])
		{
			$update_cmd .= "err_packet_in = $device_info{$device_ip}->[2]->{$port}->[4]->[5],";
		}
		else
		{
			$update_cmd .= "err_packet_in = null,";
		}

		if(defined $device_info{$device_ip}->[2]->{$port}->[4]->[6])
		{
			$update_cmd .= "err_packet_out = $device_info{$device_ip}->[2]->{$port}->[4]->[6],";
		}
		else
		{
			$update_cmd .= "err_packet_out = null,";
		}

		$update_cmd .= "datetime = '$time_now_str' where device_ip = '$device_ip' and port_index = $port";

		my $sqr_update = $dbh->prepare("$update_cmd");
		$sqr_update->execute();
		$sqr_update->finish();

#写入 rrd 文件
		if($device_info{$device_ip}->[2]->{$port}->[0] == 1)
		{
			&update_rrd($dbh,$device_ip,$port,$device_info{$device_ip}->[2]->{$port}->[4]->[1],'traffic_in',$device_info{$device_ip}->[2]->{$port}->[4]->[2],'traffic_out','traffic.rrd');
		}
		
		if($device_info{$device_ip}->[2]->{$port}->[1] == 1)
		{
			&update_rrd($dbh,$device_ip,$port,$device_info{$device_ip}->[2]->{$port}->[4]->[3],'packet_in',$device_info{$device_ip}->[2]->{$port}->[4]->[4],'packet_out','packet.rrd');
		}

		if($device_info{$device_ip}->[2]->{$port}->[2] == 1)
		{
			&update_rrd($dbh,$device_ip,$port,$device_info{$device_ip}->[2]->{$port}->[4]->[5],'err_packet_in',$device_info{$device_ip}->[2]->{$port}->[4]->[6],'err_packet_out','err_packet.rrd');
		}

#记录告警日志表		
#status
		if(defined $device_info{$device_ip}->[2]->{$port}->[3]->[0] && defined $device_info{$device_ip}->[2]->{$port}->[4]->[0] && $device_info{$device_ip}->[2]->{$port}->[3]->[0] ne $device_info{$device_ip}->[2]->{$port}->[4]->[0])
		{
			&insert_log($dbh,$device_ip,$time_now_str,$port,"状态异常: 正常状态 $device_info{$device_ip}->[2]->{$port}->[3]->[0], 当前状态 $device_info{$device_ip}->[2]->{$port}->[4]->[0]");
		}

# traffic in
		if(&bigger($device_info{$device_ip}->[2]->{$port}->[3]->[1]->[0],$device_info{$device_ip}->[2]->{$port}->[4]->[1]) || &smaller($device_info{$device_ip}->[2]->{$port}->[3]->[1]->[1],$device_info{$device_ip}->[2]->{$port}->[4]->[1]))
		{
			my $msg;
			if(&bigger($device_info{$device_ip}->[2]->{$port}->[3]->[1]->[0],$device_info{$device_ip}->[2]->{$port}->[4]->[1]))
			{
				$msg = "入向流量大于门限值: 门限值 $device_info{$device_ip}->[2]->{$port}->[3]->[1]->[0], 当前值 $device_info{$device_ip}->[2]->{$port}->[4]->[1]";
			}
			else
			{
				$msg = "入向流量小于门限值: 门限值 $device_info{$device_ip}->[2]->{$port}->[3]->[1]->[1], 当前值 $device_info{$device_ip}->[2]->{$port}->[4]->[1]";
			}
			&insert_log($dbh,$device_ip,$time_now_str,$port,$msg);
		}

# traffic out
		if(&bigger($device_info{$device_ip}->[2]->{$port}->[3]->[2]->[0],$device_info{$device_ip}->[2]->{$port}->[4]->[2]) || &smaller($device_info{$device_ip}->[2]->{$port}->[3]->[2]->[1],$device_info{$device_ip}->[2]->{$port}->[4]->[2]))
		{
			my $msg;
			if(&bigger($device_info{$device_ip}->[2]->{$port}->[3]->[2]->[0],$device_info{$device_ip}->[2]->{$port}->[4]->[2]))
			{
				$msg = "出向流量大于门限值: 门限值 $device_info{$device_ip}->[2]->{$port}->[3]->[2]->[0], 当前值 $device_info{$device_ip}->[2]->{$port}->[4]->[2]";
			}
			else
			{
				$msg = "出向流量小于门限值: 门限值 $device_info{$device_ip}->[2]->{$port}->[3]->[2]->[1], 当前值 $device_info{$device_ip}->[2]->{$port}->[4]->[2]";
			}
			&insert_log($dbh,$device_ip,$time_now_str,$port,$msg);
		}

# packet in
		if(&bigger($device_info{$device_ip}->[2]->{$port}->[3]->[3]->[0],$device_info{$device_ip}->[2]->{$port}->[4]->[3]) || &smaller($device_info{$device_ip}->[2]->{$port}->[3]->[3]->[1],$device_info{$device_ip}->[2]->{$port}->[4]->[3]))
		{
			my $msg;
			if(&bigger($device_info{$device_ip}->[2]->{$port}->[3]->[3]->[0],$device_info{$device_ip}->[2]->{$port}->[4]->[3]))
			{
				$msg = "入向非广播包大于门限值: 门限值 $device_info{$device_ip}->[2]->{$port}->[3]->[3]->[0], 当前值 $device_info{$device_ip}->[2]->{$port}->[4]->[3]";
			}
			else
			{
				$msg = "入向非广播包小于门限值: 门限值 $device_info{$device_ip}->[2]->{$port}->[3]->[3]->[1], 当前值 $device_info{$device_ip}->[2]->{$port}->[4]->[3]";
			}
			&insert_log($dbh,$device_ip,$time_now_str,$port,$msg);
		}

# packet out
		if(&bigger($device_info{$device_ip}->[2]->{$port}->[3]->[4]->[0],$device_info{$device_ip}->[2]->{$port}->[4]->[4]) || &smaller($device_info{$device_ip}->[2]->{$port}->[3]->[4]->[1],$device_info{$device_ip}->[2]->{$port}->[4]->[4]))
		{
			my $msg;
			if(&bigger($device_info{$device_ip}->[2]->{$port}->[3]->[4]->[0],$device_info{$device_ip}->[2]->{$port}->[4]->[4]))
			{
				$msg = "出向非广播包大于门限值: 门限值 $device_info{$device_ip}->[2]->{$port}->[3]->[4]->[0], 当前值 $device_info{$device_ip}->[2]->{$port}->[4]->[4]";
			}
			else
			{
				$msg = "出向非广播包小于门限值: 门限值 $device_info{$device_ip}->[2]->{$port}->[3]->[4]->[1], 当前值 $device_info{$device_ip}->[2]->{$port}->[4]->[4]";
			}
			&insert_log($dbh,$device_ip,$time_now_str,$port,$msg);
		}

# err packet in
		if(&bigger($device_info{$device_ip}->[2]->{$port}->[3]->[5]->[0],$device_info{$device_ip}->[2]->{$port}->[4]->[5]) || &smaller($device_info{$device_ip}->[2]->{$port}->[3]->[5]->[1],$device_info{$device_ip}->[2]->{$port}->[4]->[5]))
		{
			my $msg;
			if(&bigger($device_info{$device_ip}->[2]->{$port}->[3]->[5]->[0],$device_info{$device_ip}->[2]->{$port}->[4]->[5]))
			{
				$msg = "入向错包大于门限值: 门限值 $device_info{$device_ip}->[2]->{$port}->[3]->[5]->[0], 当前值 $device_info{$device_ip}->[2]->{$port}->[4]->[5]";
			}
			else
			{
				$msg = "入向错包小于门限值: 门限值 $device_info{$device_ip}->[2]->{$port}->[3]->[5]->[1], 当前值 $device_info{$device_ip}->[2]->{$port}->[4]->[5]";
			}
			&insert_log($dbh,$device_ip,$time_now_str,$port,$msg);
		}

# err packet out
		if(&bigger($device_info{$device_ip}->[2]->{$port}->[3]->[6]->[0],$device_info{$device_ip}->[2]->{$port}->[4]->[6]) || &smaller($device_info{$device_ip}->[2]->{$port}->[3]->[6]->[1],$device_info{$device_ip}->[2]->{$port}->[4]->[6]))
		{
			my $msg;
			if(&bigger($device_info{$device_ip}->[2]->{$port}->[3]->[6]->[0],$device_info{$device_ip}->[2]->{$port}->[4]->[6]))
			{
				$msg = "出向错包大于门限值: 门限值 $device_info{$device_ip}->[2]->{$port}->[3]->[6]->[0], 当前值 $device_info{$device_ip}->[2]->{$port}->[4]->[6]";
			}
			else
			{
				$msg = "出向错包小于门限值: 门限值 $device_info{$device_ip}->[2]->{$port}->[3]->[6]->[1], 当前值 $device_info{$device_ip}->[2]->{$port}->[4]->[6]";
			}
			&insert_log($dbh,$device_ip,$time_now_str,$port,$msg);
		}
	}
}

sub bigger
{
	my($high_thold,$cur_val) = @_;
	if(defined $high_thold && defined $cur_val && ($cur_val > $high_thold))
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

sub smaller
{
	my($low_thold,$cur_val) = @_;
	if(defined $low_thold && defined $cur_val && ($cur_val < $low_thold))
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

sub insert_log
{
	my($dbh,$device_ip,$time_now,$port,$log) = @_;
	my $sqr_insert;

	if(defined $port)
	{
		$sqr_insert = $dbh->prepare("insert into snmp_interface_log(device_ip,datetime,port_index,context) values ('$device_ip','$time_now',$port,'$log')");
	}
	else
	{
		$sqr_insert = $dbh->prepare("insert into snmp_interface_log(device_ip,datetime,context) values ('$device_ip','$time_now','$log')");
	}
	$sqr_insert->execute();
	$sqr_insert->finish();

	if($debug == 1)
	{
		if(defined $port)
		{
			print "$device_ip\t$port\t$log\n";
		}
		else
		{
			print "$device_ip\t$log\n";
		}
	}
}

sub not_enable_rrd
{
	my($dbh,$device_ip,$port,$rrdfile,$file_name,$col_name,$rrd_col_in,$rrd_col_out) = @_;

	my $dir = "/opt/freesvr/nm/$device_ip/interface/$port";
	if(defined $rrdfile)
	{
		if(-e $rrdfile)
		{
			my $file = $dir."/$file_name";
			if($rrdfile eq $file)
			{
				&update_rrd($dbh,$device_ip,$port,undef,$rrd_col_in,undef,$rrd_col_out,$file_name);
			}
			else
			{
				unlink $rrdfile;
				my $sqr_update = $dbh->prepare("update snmp_interface set $col_name = null where device_ip = '$device_ip' and port_index = $port");
				$sqr_update->execute();
				$sqr_update->finish();
			}
		}
		else
		{
			my $sqr_update = $dbh->prepare("update snmp_interface set $col_name = null where device_ip = '$device_ip' and port_index = $port");
			$sqr_update->execute();
			$sqr_update->finish();
		}
	}
}

sub update_nan
{
	my($dbh,$device_ip,$port) = @_;

	my $sqr_cmd;
	if(defined $port)
	{
		$sqr_cmd = "select port_index,enable,trafffic_rrdfile,packet_rrdfile,err_packet_rrdfile from snmp_interface where device_ip = '$device_ip' and port_index = $port";
	}
	else
	{
		$sqr_cmd = "select port_index,enable,trafffic_rrdfile,packet_rrdfile,err_packet_rrdfile from snmp_interface where device_ip = '$device_ip'";
	}

	my $sqr_select_rrd = $dbh->prepare("$sqr_cmd");
	$sqr_select_rrd->execute();
	while(my $ref_select_rrd = $sqr_select_rrd->fetchrow_hashref())
	{
		my $port = $ref_select_rrd->{"port_index"};
		my $enable = $ref_select_rrd->{"enable"};
		my $trafffic_rrdfile = $ref_select_rrd->{"trafffic_rrdfile"};
		my $packet_rrdfile = $ref_select_rrd->{"packet_rrdfile"};
		my $err_packet_rrdfile = $ref_select_rrd->{"err_packet_rrdfile"};

		if(! defined $enable || $enable != 1)
		{
			my $sqr_update = $dbh->prepare("update snmp_interface set datetime = null, traffic_in = null, traffic_out = null, packet_in = null, packet_out = null, err_packet_in = null, err_packet_out = null where device_ip = '$device_ip' and port_index = $port");
			$sqr_update->execute();
			$sqr_update->finish();

			my $sqr_delete = $dbh->prepare("delete from snmp_interface_cache where device_ip = '$device_ip' and port_index = $port");
			$sqr_delete->execute();
			$sqr_delete->finish();


			&not_enable_rrd($dbh,$device_ip,$port,$trafffic_rrdfile,'traffic.rrd','trafffic_rrdfile','traffic_in','traffic_out');
			&not_enable_rrd($dbh,$device_ip,$port,$packet_rrdfile,'packet.rrd','packet_rrdfile','packet_in','packet_out');
			&not_enable_rrd($dbh,$device_ip,$port,$err_packet_rrdfile,'err_packet.rrd','err_packet_rrdfile','err_packet_in','err_packet_out');
		}
		else
		{
			my $sqr_update = $dbh->prepare("update snmp_interface set datetime = '$time_now_str', traffic_in = null, traffic_out = null, packet_in = null, packet_out = null, err_packet_in = null, err_packet_out = null where device_ip = '$device_ip' and port_index = $port");
			$sqr_update->execute();
			$sqr_update->finish();

			&update_rrd($dbh,$device_ip,$port,undef,'traffic_in',undef,'traffic_out','traffic.rrd');
			&update_rrd($dbh,$device_ip,$port,undef,'packet_in',undef,'packet_out','packet.rrd');
			&update_rrd($dbh,$device_ip,$port,undef,'err_packet_in',undef,'err_packet_out','err_packet.rrd');
		}
	}
	$sqr_select_rrd->finish();

}

sub update_rrd
{
	my($dbh,$device_ip,$port,$val_in,$dsname_in,$val_out,$dsname_out,$rrdfile) = @_;

	my $start_time = time;
	$start_time = (floor($start_time/300))*300;

	my $dir = "/opt/freesvr/nm/$device_ip/interface/$port";
	unless(-e "/opt/freesvr/nm/$device_ip/")
	{
		mkdir "/opt/freesvr/nm/$device_ip/",0755;
	}

	unless(-e "/opt/freesvr/nm/$device_ip/interface")
	{
		mkdir "/opt/freesvr/nm/$device_ip/interface",0755;
	}

	unless(-e $dir)
	{
		mkdir $dir,0755;
	}

	my $file = $dir."/$rrdfile";

	unless(-e $file)
	{
		my $create_time = $start_time - 300;
		RRDs::create($file,
				'--start', "$create_time",
				'--step', '300',        
				"DS:$dsname_in:GAUGE:600:U:U",
				"DS:$dsname_out:GAUGE:600:U:U",
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

	my $col_name;
	if($rrdfile =~ /^traffic/i) {$col_name = "trafffic_rrdfile";}
	elsif($rrdfile =~ /^err_packet/i){$col_name = "err_packet_rrdfile";}
	else{$col_name = "packet_rrdfile";}

	my $sqr_select_rrd = $dbh->prepare("select $col_name from snmp_interface where device_ip = '$device_ip' and port_index = $port");
	$sqr_select_rrd->execute();
	my $ref_select_rrd = $sqr_select_rrd->fetchrow_hashref();
	my $rrdfile_name = $ref_select_rrd->{"$col_name"};
	$sqr_select_rrd->finish();

	if(!defined $rrdfile_name || $rrdfile_name ne $file)
	{
		if(defined $rrdfile_name){unlink $rrdfile_name;}
		my $sqr_update = $dbh->prepare("update snmp_interface set $col_name = '$file' where device_ip = '$device_ip' and port_index = $port");
		$sqr_update->execute();
		$sqr_update->finish();
	}

	unless(defined $val_in)
	{
		$val_in = 'U';
	}

	unless(defined $val_out)
	{
		$val_out = 'U';
	}

	RRDs::update(
			$file,
			'--', join(':', "$start_time", "$val_in","$val_out"),
			);
}
