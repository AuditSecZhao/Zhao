#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use DBD::mysql;
use Expect;
use RRDs;
use POSIX qw/ceil floor/;

our $debug = 1;
our $status_path = '/tmp/remote_server_status/';
our $max_process_num = 5;
our $exist_process = 0;
our $process_time = 120;			#进程存活时间
our $host;							#用于子进程记录自己的host
our $root_path = "linux_root";		#linux根目录代名词,避免 / 的出现

our $time_now_utc = time;
my($min,$hour,$mday,$mon,$year) = (localtime $time_now_utc)[1..5];
($min,$hour,$mday,$mon,$year) = (sprintf("%02d", $min),sprintf("%02d", $hour),sprintf("%02d", $mday),sprintf("%02d", $mon + 1),$year+1900);
our $time_now_str = "$year$mon$mday$hour$min"."00";

my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});

my $utf8 = $dbh->prepare("set names utf8");
$utf8->execute();
$utf8->finish();

our @ref_ip_arr;
my $sqr_select = $dbh->prepare("select device_ip,device_type,monitor,snmpkey from servers where monitor!=0 group by device_ip");
$sqr_select->execute();
while(my $ref_select = $sqr_select->fetchrow_hashref())
{       
	my $device_ip = $ref_select->{"device_ip"};
	my $device_type = $ref_select->{"device_type"};
	my $monitor = $ref_select->{"monitor"};
	my $snmpkey = $ref_select->{"snmpkey"};

	if($monitor == 1)
	{
		&get_sys_runtime($dbh,$device_ip,$snmpkey);
	}

	if($monitor == 1)
	{
		my @host = ($monitor,$device_ip,$device_type,$snmpkey);
		push @ref_ip_arr,\@host;
	}
	elsif($monitor == 2)
	{
		my @host = ($monitor,$device_ip);
		push @ref_ip_arr,\@host;    
	}
	elsif($monitor == 3)
	{
		my @host = ($monitor,$device_ip);
		push @ref_ip_arr,\@host;
	}
}                   
$sqr_select->finish();
my $rc = $dbh->disconnect;

if(scalar @ref_ip_arr == 0) {exit;}

if($max_process_num > scalar @ref_ip_arr){$max_process_num = scalar @ref_ip_arr;}
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
				defined(my $pid = fork) or die "cannot fork:$!";
				unless($pid){
					exec "/home/wuxiaolong/3_status/snmp_ssh_warning.pl";
				}
				exit;
			}
		}
	}
}

sub fork_process
{
	my $temp = shift @ref_ip_arr;
	unless(defined $temp){return;}
	my $pid = fork();
	if (!defined($pid))
	{
		print "Error in fork: $!";
		exit 1;
	}

	if ($pid == 0)
	{
		$SIG{ALRM}=\&alarm_process;
		$host = $temp->[1];
		alarm($process_time);
		if($temp->[0] == 1)
		{
			if($temp->[2] == 2){&linux_snmp('snmp',$temp->[1],$temp->[3]);}
			elsif($temp->[2] == 4 || $temp->[2] == 20){&windows_snmp('snmp',$temp->[1],$temp->[3]);}
			elsif($temp->[2] == 11){&cisco_snmp('snmp',$temp->[1],$temp->[3]);}
		}
		elsif($temp->[0] == 2)
		{
			&ssh_status('ssh',$temp->[1]);
		}
		elsif($temp->[0] == 3)
		{
			&read_file('读文件',$temp->[1]);
		}
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

sub linux_snmp
{
	my($monitor,$device_ip,$snmpkey) = @_;
	unless(defined $snmpkey) {return;}

	my $status = 1;

	my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});

	my $utf8 = $dbh->prepare("set names utf8");
	$utf8->execute();
	$utf8->finish();

	if($debug == 1)
	{
		print "主机 $device_ip 开始SNMP获取状态\n";
	}

	my $cpu = `snmpwalk -v 2c -c $snmpkey $device_ip .1.3.6.1.4.1.2021.11.9.0 2>&1`;

	if($cpu =~ /Timeout.*No Response from/i)
	{
		if($debug == 1)
		{
			print "主机 $device_ip SNMP无法连接\n";
		}

		&err_process($dbh,$monitor,$device_ip,7,'主机SNMP无法连接',$time_now_str,0,undef); 
		return;
	}

	if($cpu =~ /INTEGER\s*:\s*(\d+)/i)
	{
		$cpu = $1;
	}
	&insert_into_nondisk($dbh,$device_ip,'cpu',$cpu,$time_now_str);
	&update_rrd($dbh,$device_ip,'cpu',$cpu,undef,undef);
	my $tmp_status = &warning_func($dbh,$time_now_str,$monitor,$device_ip,$cpu,'cpu',undef);
	if($status == 1 && $tmp_status != 1)
	{
		$status = $tmp_status;
	}

	if($debug == 1)
	{
		print "主机 $device_ip cpu:$cpu\n";
	}

	my $memtotal=0;my $memavail=0;my $memcache=0;my $membuff=0;my $swaptotal=0;my $swapavail=0;
	foreach(`snmpwalk -v 2c -c $snmpkey $device_ip .1.3.6.1.4.1.2021.4 2>&1`)
	{
		if($_ =~ /memTotalReal/i && $_ =~ /INTEGER\s*:\s*(\d+)/i){$memtotal = $1;}
		if($_ =~ /memAvailReal/i && $_ =~ /INTEGER\s*:\s*(\d+)/i){$memavail = $1;}
		if($_ =~ /memCached/i && $_ =~ /INTEGER\s*:\s*(\d+)/i){$memcache = $1;}
		if($_ =~ /memBuffer/i && $_ =~ /INTEGER\s*:\s*(\d+)/i){$membuff = $1;}
		if($_ =~ /memTotalSwap/i && $_ =~ /INTEGER\s*:\s*(\d+)/i){$swaptotal = $1;}
		if($_ =~ /memAvailSwap/i && $_ =~ /INTEGER\s*:\s*(\d+)/i){$swapavail = $1;}
	}

	my $mem = floor(($memtotal-$memavail-$memcache-$membuff)/$memtotal*100);
	&insert_into_nondisk($dbh,$device_ip,'memory',$mem,$time_now_str);
	&update_rrd($dbh,$device_ip,'memory',$mem,undef,undef);
	$tmp_status = &warning_func($dbh,$time_now_str,$monitor,$device_ip,$mem,'memory',undef);
	if($status == 1 && $tmp_status != 1)
	{             
		$status = $tmp_status;
	}   

	if($debug == 1)
	{
		print "主机 $device_ip mem:$mem\n";
	}

	if($swaptotal > 0)
	{
		my $swap = floor(($swaptotal-$swapavail)/$swaptotal*100);

		&insert_into_nondisk($dbh,$device_ip,'swap',$swap,$time_now_str);
		&update_rrd($dbh,$device_ip,'swap',$swap,undef,undef);
		$tmp_status = &warning_func($dbh,$time_now_str,$monitor,$device_ip,$swap,'swap',undef);
		if($status == 1 && $tmp_status != 1)
		{             
			$status = $tmp_status;
		}   

		if($debug == 1)
		{
			print "主机 $device_ip  swap:$swap\n";
		}
	}

	my %disk_num;
	foreach(`snmpwalk -v 2c -c $snmpkey $device_ip 1.3.6.1.2.1.25.2 2>&1`)
	{
		if($_ =~ /hrStorageDescr.(\d+).*STRING\s*:\s*(\/.*)$/i)
		{
			push @{$disk_num{$1}},$2;
		}

		if($_ =~ /hrStorageSize.(\d+).*INTEGER\s*:\s*(\d+)$/i)
		{
			if(exists $disk_num{$1})
			{
				push @{$disk_num{$1}},$2;
			}
		}
		if($_ =~ /hrStorageUsed.(\d+).*INTEGER\s*:\s*(\d+)$/i)
		{
			if(exists $disk_num{$1})
			{
				$disk_num{$1}->[1] = $2/$disk_num{$1}->[1];
				$disk_num{$1}->[1] = floor($disk_num{$1}->[1]*100);
			}
		}
	}

	foreach(keys %disk_num)
	{
		&insert_into_disk($dbh,$device_ip,$disk_num{$_}->[0],$disk_num{$_}->[1],$time_now_str);
		$tmp_status = &warning_func($dbh,$time_now_str,$monitor,$device_ip,$disk_num{$_}->[1],'disk',$disk_num{$_}->[0]);
		if($status == 1 && $tmp_status != 1)
		{             
			$status = $tmp_status;
		}   

		my $disk_name = $disk_num{$_}->[0];
		$disk_name =~ s/^\///;
		$disk_name =~ s/\//-/g;

		if($disk_name eq ""){$disk_name = $root_path;}

		&update_rrd($dbh,$device_ip,$disk_name,$disk_num{$_}->[1],$disk_num{$_}->[0],undef);

		if($debug == 1)
		{
			print "主机 $device_ip disk:$disk_name val:$disk_num{$_}->[1]\n";
		}
	}

	my $sqr_update = $dbh->prepare("update servers set status = $status where device_ip = '$device_ip' and monitor!=0");
	$sqr_update->execute();
	$sqr_update->finish();

	if($debug == 1)
	{
		print "主机 $device_ip SNMP状态获取完成\n";
	}
}

sub windows_snmp
{
	my($monitor,$device_ip,$snmpkey) = @_;
	unless(defined $snmpkey) {return;}

	my $status = 1;

	my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});

	my $utf8 = $dbh->prepare("set names utf8");
	$utf8->execute();
	$utf8->finish();

	if($debug == 1)
	{
		print "主机 $device_ip 开始SNMP获取状态\n";
	}

	my $cpu_num = 0;my $cpu_value = 0;
	foreach(`snmpwalk -v 2c -c $snmpkey $device_ip .1.3.6.1.2.1.25.3.3 2>&1`)
	{
		if($_ =~ /Timeout.*No Response from/i)
		{
			&err_process($dbh,$monitor,$device_ip,7,'主机SNMP无法连接',$time_now_str,0,undef); 

			if($debug == 1)
			{
				print "主机 $device_ip SNMP无法连接\n";
			}
			return;
		}

		if($_ =~ /hrProcessorLoad/i && $_ =~ /INTEGER\s*:\s*(\d+)/i)
		{
			$cpu_value += $1;
			++$cpu_num;
		}
	}
	$cpu_value = floor($cpu_value/$cpu_num);

	&insert_into_nondisk($dbh,$device_ip,'cpu',$cpu_value,$time_now_str);
	&update_rrd($dbh,$device_ip,'cpu',$cpu_value,undef,undef);
	my $tmp_status = &warning_func($dbh,$time_now_str,$monitor,$device_ip,$cpu_value,'cpu',undef);
	if($status == 1 && $tmp_status != 1)
	{
		$status = $tmp_status;
	}

	if($debug == 1)
	{
		print "主机 $device_ip cpu:$cpu_value\n";
	}

	my %disk_num;
	foreach(`snmpwalk -v 2c -c $snmpkey $device_ip .1.3.6.1.2.1.25.2 2>&1`)
	{
		if($_ =~ /hrStorageDescr\.(\d+).*STRING\s*:\s*(\S+)\s*Label/i)
		{
			push @{$disk_num{$1}},$2;
		}

		if($_ =~ /hrStorageDescr\.(\d+).*STRING\s*:\s*(.*Memory)/i)
		{
			push @{$disk_num{$1}},$2;
		}

		if($_ =~ /hrStorageSize\.(\d+).*INTEGER\s*:\s*(\d+)/i)
		{
			if(exists $disk_num{$1})
			{
				push @{$disk_num{$1}},$2;
			}
		}

		if($_ =~ /hrStorageUsed.(\d+).*INTEGER\s*:\s*(\d+)$/i)
		{
			if(exists $disk_num{$1})
			{
				$disk_num{$1}->[1] = $2/$disk_num{$1}->[1];
				$disk_num{$1}->[1] = floor($disk_num{$1}->[1]*100);
			}
		}
	}

	foreach(keys %disk_num)
	{
		if($disk_num{$_}->[0] =~ /Virtual/i)
		{
			&insert_into_nondisk($dbh,$device_ip,'swap',$disk_num{$_}->[1],$time_now_str);
			&update_rrd($dbh,$device_ip,'swap',$disk_num{$_}->[1],undef,undef);
			$tmp_status = &warning_func($dbh,$time_now_str,$monitor,$device_ip,$disk_num{$_}->[1],'swap',undef);
			if($status == 1 && $tmp_status != 1)
			{             
				$status = $tmp_status;
			}   

			if($debug == 1)
			{
				print "主机 $device_ip swap:$disk_num{$_}->[1]\n";
			}
		}
		elsif($disk_num{$_}->[0] =~ /Physical/i)
		{
			&insert_into_nondisk($dbh,$device_ip,'memory',$disk_num{$_}->[1],$time_now_str);
			&update_rrd($dbh,$device_ip,'memory',$disk_num{$_}->[1],undef,undef);
			$tmp_status = &warning_func($dbh,$time_now_str,$monitor,$device_ip,$disk_num{$_}->[1],'memory',undef);
			if($status == 1 && $tmp_status != 1)
			{             
				$status = $tmp_status;
			}   

			if($debug == 1)
			{
				print "主机 $device_ip mem:$disk_num{$_}->[1]\n";
			}
		}
		else
		{
			$disk_num{$_}->[0] =~ s/:\\/_driver/g;
			&insert_into_disk($dbh,$device_ip,$disk_num{$_}->[0],$disk_num{$_}->[1],$time_now_str);
			$tmp_status = &warning_func($dbh,$time_now_str,$monitor,$device_ip,$disk_num{$_}->[1],'disk',$disk_num{$_}->[0]);
			if($status == 1 && $tmp_status != 1)
			{             
				$status = $tmp_status;
			}   

			my $disk_name = $disk_num{$_}->[0];
			$disk_name =~ s/^\///;
			$disk_name =~ s/\//-/g;

			if($disk_name eq ""){$disk_name = $root_path;}

			&update_rrd($dbh,$device_ip,$disk_name,$disk_num{$_}->[1],$disk_num{$_}->[0],undef);
			if($debug == 1)
			{
				print "主机 $device_ip disk:$disk_name val:$disk_num{$_}->[1]\n";
			}
		}
	}

	my $sqr_update = $dbh->prepare("update servers set status = $status where device_ip = '$device_ip' and monitor!=0");
	$sqr_update->execute();
	$sqr_update->finish();

	if($debug == 1)
	{
		print "主机 $device_ip SNMP状态获取完成\n";
	}
}

sub cisco_snmp
{
	my($monitor,$device_ip,$snmpkey) = @_;
	unless(defined $snmpkey) {return;}

	my $status = 1;

	my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});

	my $utf8 = $dbh->prepare("set names utf8");
	$utf8->execute();
	$utf8->finish();

	if($debug == 1)
	{
		print "主机 $device_ip 开始SNMP获取状态\n";
	}

	my $cpu_num = 0;my $cpu_value = 0;
	foreach(`snmpwalk -v 2c -c $snmpkey $device_ip .1.3.6.1.4.1.9.9.109.1.1.1.1.5 2>&1`)
	{
		if($_ =~ /Timeout.*No Response from/i)
		{
			&err_process($dbh,$monitor,$device_ip,7,'主机SNMP无法连接',$time_now_str,1,undef); 

			if($debug == 1)
			{
				print "主机 $device_ip SNMP无法连接\n";
			}
			return;
		}

		if($_ =~ /Gauge32\s*:\s*(\d+)$/i)
		{
			++$cpu_num;
			$cpu_value += $1;
		}
	}
	$cpu_value = floor($cpu_value/$cpu_num);

	&insert_into_nondisk($dbh,$device_ip,'cpu',$cpu_value,$time_now_str);
	&update_rrd($dbh,$device_ip,'cpu',$cpu_value,undef,undef);
	my $tmp_status = &warning_func($dbh,$time_now_str,$monitor,$device_ip,$cpu_value,'cpu',undef);
	if($status == 1 && $tmp_status != 1)
	{
		$status = $tmp_status;
	}

	if($debug == 1)
	{
		print "主机 $device_ip cpu:$cpu_value\n";
	}

	my $mem_used = 0;my $mem_free = 0;my $mem = 0;
	foreach(`snmpwalk -v 2c -c $snmpkey $device_ip 1.3.6.1.4.1.9.9.48.1.1.1`)
	{
		if($_ =~ /\.9\.9\.48\.1\.1\.1\.5\.1/i && $_ =~ /Gauge32\s*:\s*(\d+)$/i){$mem_used = $1;}
		if($_ =~ /\.9\.9\.48\.1\.1\.1\.6\.1/i && $_ =~ /Gauge32\s*:\s*(\d+)$/i){$mem_free = $1;}
	}       
	$mem = floor($mem_used/($mem_used+$mem_free)*100);

	&insert_into_nondisk($dbh,$device_ip,'memory',$mem,$time_now_str);
	&update_rrd($dbh,$device_ip,'memory',$mem,undef,undef);
	$tmp_status = &warning_func($dbh,$time_now_str,$monitor,$device_ip,$mem,'memory',undef);
	if($status == 1 && $tmp_status != 1)
	{             
		$status = $tmp_status;
	}   

	if($debug == 1)
	{
		print "主机 $device_ip mem:$mem\n";
	}

	my $sqr_update = $dbh->prepare("update servers set status = $status where device_ip = '$device_ip' and monitor!=0");
	$sqr_update->execute();
	$sqr_update->finish();

	if($debug == 1)
	{
		print "主机 $device_ip SNMP状态获取完成\n";
	}
}

sub ssh_status
{
	my($monitor,$des_ip) = @_;

	my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});

	my $utf8 = $dbh->prepare("set names utf8");
	$utf8->execute();
	$utf8->finish();

	my $sqr_select = $dbh->prepare("select login_method,username,udf_decrypt(cur_password),port from devices where master_user=1 and device_ip = '$des_ip'");
	$sqr_select->execute();
	my $ref_select = $sqr_select->fetchrow_hashref();
	my $user = $ref_select->{"username"};
	my $passwd = $ref_select->{"udf_decrypt(cur_password)"};
	my $port = $ref_select->{"port"};
	$sqr_select->finish();

	my $cmd = "ssh -l $user $des_ip -p $port";
#	print $cmd,"\n";

	if($debug == 1)
	{
		print "主机 $des_ip 开始ssh: ssh -l $user $des_ip -p $port\n";
	}

	my $exp = Expect->new;
	$exp->log_stdout(0);
	$exp->spawn($cmd);
	$exp->debug(0);

	my @results = $exp->expect(20,[
			qr/password/i,
			sub {
			my $self = shift ;

			$self->send_slow(0.1,"$passwd\n");
			}
			],
			[
			qr/yes\/no/i,
			sub {
			my $self = shift ;
			$self->send_slow(0.1,"yes\n");
			exp_continue;
			}
			],
			);

	if(defined $results[1])
	{
		my $errno;
		if($results[1] =~ /(\d+).*:.*/i) 
		{
			$errno = $1;
		}
		else 
		{
			&err_process($dbh,$monitor,$des_ip,8,$results[1],$time_now_str,0,undef); 
			if($debug == 1)
			{
				print "主机 $des_ip 其他错误退出\n";
			}
			return;
		}

		my $output = $exp->before();
		my @context = split /\n/,$output;

		if($errno == 1)
		{
			&err_process($dbh,$monitor,$des_ip,2,'ssh cmd timeout',$time_now_str,0,undef); 
			if($debug == 1)
			{
				print "主机 $des_ip ssh命令超时\n";
			}
			return;
		}
		elsif($errno == 3)
		{
			foreach my $line(@context)
			{
				if($line =~ /No\s*route\s*to\s*host/i)
				{
					&err_process($dbh,$monitor,$des_ip,3,"no route to dst host:$des_ip",$time_now_str,0,undef); 
					if($debug == 1)
					{
						print "主机 $des_ip no route to dst host\n";
					}
					return;
				}

				if($line =~ /Connection\s*refused/i)
				{
					&err_process($dbh,$monitor,$des_ip,4,"connection refused by dst host:$des_ip, maybe sshd is closed",$time_now_str,0,undef); 
					if($debug == 1)
					{
						print "主机 $des_ip connection refused, maybe sshd is closed\n";
					}
					return;
				}

				if($line =~ /Host\s*key\s*verification\s*failed/i)
				{
					&err_process($dbh,$monitor,$des_ip,6,"Host key verification failed:$des_ip",$time_now_str,0,undef); 
					if($debug == 1)
					{
						print "主机 $des_ip Host key verification failed\n";
					}
					return;
				}
			}
		}
		else
		{
			&err_process($dbh,$monitor,$des_ip,8,$results[1],$time_now_str,0,undef); 
			if($debug == 1)
			{
				print "主机 $des_ip 其他错误退出\n";
			}
			return;
		}
	}

	$exp->expect(3, undef);

	my $output = $exp->before();
	my @context = split /\n/,$output;
	foreach my $line(@context)
	{
		if($line =~ /Permission\s*denied/i)
		{
			&err_process($dbh,$monitor,$des_ip,5,"passwd for $des_ip is wrong",$time_now_str,0,undef); 
			if($debug == 1)
			{
				print "主机 $des_ip passwd is wrong\n";
			}
			return;
		}
		elsif($line =~ /\]#/i)
		{
			if($debug == 1)
			{
				print "主机 $des_ip 登陆成功\n";
			}
			&status_monitor($dbh,$monitor,$exp,$des_ip);
			return;
		}
	}
}

sub read_file
{
	my($monitor,$device_ip) = @_;
	sleep 30;
	my $exist_file = 0;
	my @delete_files;

	my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});

	my $utf8 = $dbh->prepare("set names utf8");
	$utf8->execute();
	$utf8->finish();

	my $dir;
	opendir $dir,$status_path;
	while(my $file = readdir $dir)
	{
		if($file =~ /^\./){next;}
		my($server_ip,$time) = split /_/,$file;

		if($device_ip eq $server_ip)
		{
			my $status = 1;
			$exist_file = 1;
			open(my $fd_fr_status,"<$status_path$file");
			my $file_time;
			foreach my $line(<$fd_fr_status>)
			{
				my($name,$val) = split /\s+/,$line;
				if($name eq "time")
				{
					$file_time = $val;
				}
				elsif($name eq "cpu" || $name eq "memory" || $name eq "swap")
				{
					unless(defined $file_time)
					{
						&err_process($dbh,$monitor,$device_ip,9,'文件中没有时间值',$time,0,1); 
						print "$device_ip 文件中没有时间值\n";
						last;
					}

					&insert_into_nondisk($dbh,$device_ip,$name,$val,$time);
					&update_rrd($dbh,$device_ip,$name,$val,undef,$file_time);
					my $tmp_status = &warning_func($dbh,$time,$monitor,$device_ip,$val,$name,undef);
					if($status == 1 && $tmp_status != 1)
					{             
						$status = $tmp_status;
					}   

					if($debug == 1)
					{
						print "主机 $device_ip $name:$val\n";
					}
				}
				elsif($name =~ /process:/i)
				{
					unless(defined $file_time)
					{
						&err_process($dbh,$monitor,$device_ip,9,'文件中没有时间值',$time,0,1); 
						print "$device_ip 文件中没有时间值\n";
						last;
					}

					my $process_name = (split /:/,$name)[1];
					&insert_into_process($dbh,$device_ip,$process_name,$val,$time);
					&update_rrd_process($dbh,$device_ip,$process_name,$val,$file_time);

					if($debug == 1)
					{
						print "主机 $device_ip 进程: $process_name 状态: $val\n";
					}
				}
				elsif($name =~ /port:/i)
				{
					unless(defined $file_time)
					{
						&err_process($dbh,$monitor,$device_ip,9,'文件中没有时间值',$time,0,1); 
						print "$device_ip 文件中没有时间值\n";
						last;
					}

					my $port = (split /:/,$name)[1];
					&insert_into_port($dbh,$device_ip,$port,$val,$time);
					&update_rrd_port($dbh,$device_ip,$port,$val,$file_time);

					if($debug == 1)
					{
						print "主机 $device_ip 端口: $port 状态: $val\n";
					}
				}
				else
				{
					unless(defined $file_time)
					{
						&err_process($dbh,$monitor,$device_ip,9,'文件中没有时间值',$time,0,1);
						print "$device_ip 文件中没有时间值\n";
						last;
					}

					&insert_into_disk($dbh,$device_ip,$name,$val,$time);
					my $tmp_status = &warning_func($dbh,$time,$monitor,$device_ip,$val,'disk',$name);
					if($status == 1 && $tmp_status != 1)
					{             
						$status = $tmp_status;
					}   

					my $disk_name = $name;
					$disk_name =~ s/^\///;
					$disk_name =~ s/\//-/g;

					if($disk_name eq ""){$disk_name = $root_path;}

					&update_rrd($dbh,$device_ip,$disk_name,$val,$name,undef);

					if($debug == 1)
					{
						print "主机 $device_ip disk:$disk_name val:$val\n";
					}
				}
			}

			my $sqr_update = $dbh->prepare("update servers set status = $status where device_ip = '$device_ip' and monitor!=0");
			$sqr_update->execute();
			$sqr_update->finish();

			if($debug == 1)
			{
				print "主机 $device_ip 读文件状态获取完成\n";
			}

			close $fd_fr_status;
			push @delete_files, "$status_path$file";
		}
	}

	foreach my $tmp_file(@delete_files)
	{
		unlink $tmp_file;
	}

	if($exist_file == 0)
	{
		&err_process($dbh,$monitor,$device_ip,10,'没有找到主机对应的文件',$time_now_str,0,1);
		print "$device_ip 没有找到主机对应的文件\n";
		return;
	}
}

sub err_process
{
	my($dbh,$monitor,$host,$errno,$err_str,$cur_time,$only_cpu_mem,$process_or_port) = @_;

	my $insert;
	if(defined $err_str)
	{
		$insert = $dbh->prepare("insert into status_log(datetime,host,result,reason) values($time_now_str,'$host',$errno,'$err_str')");
	}
	else
	{
		$insert = $dbh->prepare("insert into status_log(datetime,host,result) values($time_now_str,'$host',$errno)");
	}
	$insert->execute();
	$insert->finish();

	&insert_into_nondisk($dbh,$host,'cpu',-100,$cur_time);
	&insert_into_nondisk($dbh,$host,'memory',-100,$cur_time);

	if($only_cpu_mem == 0)
	{
		&insert_into_nondisk($dbh,$host,'swap',-100,$cur_time);
		&insert_into_disk($dbh,$host,undef,-100,$cur_time);
	}

	if(defined $process_or_port)
	{
		&insert_into_process($dbh,$host,undef,-1,$cur_time);
		&insert_into_port($dbh,$host,undef,-1,$cur_time);
	}

	if($monitor ne "")
	{
		my $status = &warning_func($dbh,$cur_time,$monitor,$host,-100,undef,undef);
	}

	my $sqr_update = $dbh->prepare("update servers set status = 0 where device_ip = '$host' and monitor!=0");
	$sqr_update->execute();
	$sqr_update->finish();
}

sub status_monitor
{
	my($dbh,$monitor,$exp,$device_ip) = @_;
	my $status = 1;

	my $cmd = "/usr/bin/top -b -n 1 | head -n 5 | grep -i 'cpu'";

	$exp->send("$cmd\n");
	$exp->expect(2, undef);

	my $result = $exp->before();
	my @context = split /\n/,$result;

	foreach my $line(@context)
	{
		if($line =~ /(\d+\.\d+)%id/i)
		{
			my $cpu = $1;
			$cpu = floor(100 - $cpu);
			&insert_into_nondisk($dbh,$device_ip,'cpu',$cpu,$time_now_str);
			&update_rrd($dbh,$device_ip,'cpu',$cpu,undef,undef);
			my $tmp_status = &warning_func($dbh,$time_now_str,$monitor,$device_ip,$cpu,'cpu',undef);
			if($status == 1 && $tmp_status != 1)
			{
				$status = $tmp_status;
			}

			if($debug == 1)
			{
				print "主机 $device_ip cpu:$cpu\n";
			}
			last;
		}
	}

	$cmd = "free | grep -i 'mem'";
	$exp->send("$cmd\n");
	$exp->expect(2, undef);

	$result = $exp->before();
	@context = split /\n/,$result;

	foreach my $line(@context)
	{
		if($line =~ /^mem/i)
		{
			my($total,$used,$buffers,$cache) = (split /\s+/,$line)[1,2,5,6];
			my $memory = floor(($used-$buffers-$cache)/$total*100);
			&insert_into_nondisk($dbh,$device_ip,'memory',$memory,$time_now_str);
			&update_rrd($dbh,$device_ip,'memory',$memory,undef,undef);
			my $tmp_status = &warning_func($dbh,$time_now_str,$monitor,$device_ip,$memory,'memory',undef);
			if($status == 1 && $tmp_status != 1)
			{             
				$status = $tmp_status;
			}   

			if($debug == 1)
			{
				print "主机 $device_ip mem:$memory\n";
			}
			last;
		}
	}

	$cmd = "free | grep -i 'swap'";
	$exp->send("$cmd\n");
	$exp->expect(2, undef);

	$result = $exp->before();
	@context = split /\n/,$result;

	foreach my $line(@context)
	{
		if($line =~ /^swap/i)
		{
			my($total,$used) = (split /\s+/,$line)[1,2];
			my $swap = floor($used/$total*100);
			&insert_into_nondisk($dbh,$device_ip,'swap',$swap,$time_now_str);
			&update_rrd($dbh,$device_ip,'swap',$swap,undef,undef);
			my $tmp_status = &warning_func($dbh,$time_now_str,$monitor,$device_ip,$swap,'swap',undef);
			if($status == 1 && $tmp_status != 1)
			{             
				$status = $tmp_status;
			}   

			if($debug == 1)
			{
				print "主机 $device_ip swap:$swap\n";
			}
			last;
		}
	}

	$cmd = "df";
	$exp->send("$cmd\n");
	$exp->expect(2, undef);

	$result = $exp->before();
	@context = split /\n/,$result;

	foreach my $line(@context)
	{
		if($line =~ /(\d+)%\s*(\/\S*)/i)
		{
			my $disk_val = $1;
			my $disk_name = $2;
			if($disk_name =~ /shm/i){next;}
			&insert_into_disk($dbh,$device_ip,$disk_name,$disk_val,$time_now_str);
			my $tmp_status = &warning_func($dbh,$time_now_str,$monitor,$device_ip,$disk_val,'disk',$disk_name);
			if($status == 1 && $tmp_status != 1)
			{             
				$status = $tmp_status;
			}   

			my $disk_tmp = $disk_name;
			$disk_name =~ s/^\///;
			$disk_name =~ s/\//-/g;

			if($disk_name eq ""){$disk_name = $root_path;}

			&update_rrd($dbh,$device_ip,$disk_name,$disk_val,$disk_tmp,undef);
			if($debug == 1)
			{
				print "主机 $device_ip disk:$disk_name val: $disk_val\n";
			}
		}
	}

	my $sqr_update = $dbh->prepare("update servers set status = $status where device_ip = '$device_ip' and monitor!=0");
	$sqr_update->execute();
	$sqr_update->finish();

	if($debug == 1)
	{
		print "主机 $device_ip ssh状态获取完成\n";
	}

}

sub insert_into_nondisk
{
	my($dbh,$device_ip,$type,$value,$cur_time) = @_;

	my $sqr_select = $dbh->prepare("select count(*) from snmp_status where device_ip = '$device_ip' and type = '$type'");
	$sqr_select->execute();
	my $ref_select = $sqr_select->fetchrow_hashref();
	my $device_num = $ref_select->{"count(*)"};
	$sqr_select->finish();

	if($device_num == 0)
	{
		if($type eq 'swap' && $value < 0)				#数据库中没有swap, 此时报错,不能判断主机是否有swap, 所以先不写
		{
			return;
		}

		my $sqr_insert = $dbh->prepare("insert into snmp_status (device_ip,type) values ('$device_ip','$type')");
		$sqr_insert->execute();
		$sqr_insert->finish();

		$sqr_select = $dbh->prepare("select enable from snmp_status where device_ip = '$device_ip' and type = '$type'");
		$sqr_select->execute();
		$ref_select = $sqr_select->fetchrow_hashref();
		my $enable = $ref_select->{"enable"};
		$sqr_select->finish();

		if($enable != 1)
		{
			if($debug == 1)
			{
				my $sqr_update = $dbh->prepare("update snmp_status set enable = 1 where device_ip = '$device_ip' and type = '$type'");
				$sqr_update->execute();
				$sqr_update->finish();

				$sqr_update = $dbh->prepare("update snmp_status set value = $value, datetime = '$cur_time' where device_ip = '$device_ip' and type = '$type'");
				$sqr_update->execute();
				$sqr_update->finish();
			}
		}
		else
		{
			my $sqr_update = $dbh->prepare("update snmp_status set value = $value, datetime = '$cur_time' where device_ip = '$device_ip' and type = '$type'");
			$sqr_update->execute();
			$sqr_update->finish();
		}
	}
	else
	{
		$sqr_select = $dbh->prepare("select enable from snmp_status where device_ip = '$device_ip' and type = '$type'");
		$sqr_select->execute();
		$ref_select = $sqr_select->fetchrow_hashref();
		my $enable = $ref_select->{"enable"};
		$sqr_select->finish();

		if($enable == 1)
		{
			my $sqr_update = $dbh->prepare("update snmp_status set value = $value, datetime = '$cur_time' where device_ip = '$device_ip' and type = '$type'");
			$sqr_update->execute();
			$sqr_update->finish();
		}
		else
		{
			my $sqr_update = $dbh->prepare("update snmp_status set value = null, datetime = null where device_ip = '$device_ip' and type = '$type'");
			$sqr_update->execute();
			$sqr_update->finish();
		}
	}
}

sub insert_into_disk
{

	my($dbh,$device_ip,$disk,$value,$cur_time) = @_;

	my $disk_name;
	if(defined $disk)
	{
		$disk =~ s/\\/\\\\/g;
#		print $disk,"\n";

		$disk_name = $disk;
		$disk_name =~ s/^\///;
		$disk_name =~ s/\//-/g;
		if($disk_name eq ""){$disk_name = $root_path;}
	}

	if($value < 0)
	{
		my $sqr_select = $dbh->prepare("select count(*) from snmp_status where device_ip = '$device_ip' and type = 'disk'");
		$sqr_select->execute();
		my $ref_select = $sqr_select->fetchrow_hashref();
		my $device_num = $ref_select->{"count(*)"};
		$sqr_select->finish();

		if($device_num == 0)
		{
			my $sqr_insert = $dbh->prepare("insert into snmp_status (device_ip,type) values ('$device_ip','disk')");
			$sqr_insert->execute();
			$sqr_insert->finish();

			$sqr_select = $dbh->prepare("select enable from snmp_status where device_ip = '$device_ip' and type = 'disk'");
			$sqr_select->execute();
			$ref_select = $sqr_select->fetchrow_hashref();
			my $enable = $ref_select->{"enable"};
			$sqr_select->finish();

			if($enable != 1)
			{
				if($debug == 1)
				{
					my $sqr_update = $dbh->prepare("update snmp_status set enable = 1 where device_ip = '$device_ip' and type = 'disk'");
					$sqr_update->execute();
					$sqr_update->finish();

					$sqr_update = $dbh->prepare("update snmp_status set value = $value, datetime = '$cur_time' where device_ip = '$device_ip' and type = 'disk'");
					$sqr_update->execute();
					$sqr_update->finish();
				}
			}
			else
			{
				my $sqr_update = $dbh->prepare("update snmp_status set value = $value, datetime = '$cur_time' where device_ip = '$device_ip' and type = 'disk'");
				$sqr_update->execute();
				$sqr_update->finish();
			}
		}
		else
		{
			$sqr_select = $dbh->prepare("select seq, enable from snmp_status where device_ip = '$device_ip' and type = 'disk'");
			$sqr_select->execute();
			while($ref_select = $sqr_select->fetchrow_hashref())
			{
				my $enable = $ref_select->{"enable"};
				my $disk_seq = $ref_select->{"seq"};

				if($enable == 1)
				{
					my $sqr_update = $dbh->prepare("update snmp_status set value = $value, datetime = '$cur_time' where device_ip = '$device_ip' and type = 'disk' and seq = $disk_seq");
					$sqr_update->execute();
					$sqr_update->finish();
				}
				else
				{
					my $sqr_update = $dbh->prepare("update snmp_status set value = null, datetime = null where device_ip = '$device_ip' and type = 'disk' and seq = $disk_seq");
					$sqr_update->execute();
					$sqr_update->finish();
				}
			}
			$sqr_select->finish();
		}
	}
	else
	{
		my $sqr_select = $dbh->prepare("select count(*) from snmp_status where device_ip = '$device_ip' and type = 'disk' and disk = '$disk'");
		$sqr_select->execute();
		my $ref_select = $sqr_select->fetchrow_hashref();
		my $device_num = $ref_select->{"count(*)"};
		$sqr_select->finish();

		if($device_num == 0)
		{
			$sqr_select = $dbh->prepare("select seq from snmp_status where device_ip = '$device_ip' and type = 'disk' and disk is null");
			$sqr_select->execute();
			$ref_select = $sqr_select->fetchrow_hashref();
			my $disk_seq = $ref_select->{"seq"};
			$sqr_select->finish();

			if(defined $disk_seq)
			{
				my $sqr_delete = $dbh->prepare("delete from snmp_status where seq = $disk_seq");
				$sqr_delete->execute();
				$sqr_delete->finish();
			}

			my $sqr_insert = $dbh->prepare("insert into snmp_status (device_ip,type,disk) values ('$device_ip','disk','$disk')");
			$sqr_insert->execute();
			$sqr_insert->finish();

			$sqr_select = $dbh->prepare("select enable from snmp_status where device_ip = '$device_ip' and type = 'disk' and disk = '$disk'");
			$sqr_select->execute();
			$ref_select = $sqr_select->fetchrow_hashref();
			my $enable = $ref_select->{"enable"};
			$sqr_select->finish();

			if($enable != 1)
			{
				if($debug == 1)
				{
					my $sqr_update = $dbh->prepare("update snmp_status set enable = 1 where device_ip = '$device_ip' and type = 'disk' and disk = '$disk'");
					$sqr_update->execute();
					$sqr_update->finish();

					$sqr_update = $dbh->prepare("update snmp_status set value = $value, datetime = '$cur_time' where device_ip = '$device_ip' and type = 'disk' and disk = '$disk'");
					$sqr_update->execute();
					$sqr_update->finish();
				}
			}
			else
			{
				my $sqr_update = $dbh->prepare("update snmp_status set value = $value, datetime = '$cur_time' where device_ip = '$device_ip' and type = 'disk' and disk = '$disk'");
				$sqr_update->execute();
				$sqr_update->finish();
			}

		}
		else
		{
			$sqr_select = $dbh->prepare("select enable from snmp_status where device_ip = '$device_ip' and type = 'disk' and disk = '$disk'");
			$sqr_select->execute();
			$ref_select = $sqr_select->fetchrow_hashref();
			my $enable = $ref_select->{"enable"};
			$sqr_select->finish();

			if($enable == 1)
			{
				my $sqr_update = $dbh->prepare("update snmp_status set value = $value, datetime = '$cur_time' where device_ip = '$device_ip' and type = 'disk' and disk = '$disk'");
				$sqr_update->execute();
				$sqr_update->finish();
			}
			else
			{
				my $sqr_update = $dbh->prepare("update snmp_status set value = null, datetime = null where device_ip = '$device_ip' and type = 'disk' and disk = '$disk'");
				$sqr_update->execute();
				$sqr_update->finish();
			}
		}
	}
}

sub insert_into_process
{
	my($dbh,$device_ip,$name,$val,$cur_time) = @_;

	unless(defined $name)
	{
		my $sqr_update = $dbh->prepare("update snmp_check_process set process_status = $val, datetime = '$cur_time' where device_ip = '$device_ip'");
		$sqr_update->execute();
		$sqr_update->finish();
		return;
	}

	my $sqr_select = $dbh->prepare("select count(*) from snmp_check_process where device_ip = '$device_ip' and process = '$name'");
	$sqr_select->execute();
	my $ref_select = $sqr_select->fetchrow_hashref();
	my $device_num = $ref_select->{"count(*)"};
	$sqr_select->finish();

	if($device_num == 0)
	{
		my $sqr_insert = $dbh->prepare("insert into snmp_check_process (device_ip,process) values ('$device_ip','$name')");
		$sqr_insert->execute();
		$sqr_insert->finish();

		$sqr_select = $dbh->prepare("select enable from snmp_check_process where device_ip = '$device_ip' and process = '$name'");
		$sqr_select->execute();
		$ref_select = $sqr_select->fetchrow_hashref();
		my $enable = $ref_select->{"enable"};
		$sqr_select->finish();

		if($enable != 1)
		{
			if($debug == 1)
			{
				my $sqr_update = $dbh->prepare("update snmp_check_process set enable = 1 where device_ip = '$device_ip' and process = '$name'");
				$sqr_update->execute();
				$sqr_update->finish();

				$sqr_update = $dbh->prepare("update snmp_check_process set process_status = $val, datetime = '$cur_time' where device_ip = '$device_ip' and process = '$name'");
				$sqr_update->execute();
				$sqr_update->finish();
			}
		}
		else
		{
			my $sqr_update = $dbh->prepare("update snmp_check_process set process_status = $val, datetime = '$cur_time' where device_ip = '$device_ip' and process = '$name'");
			$sqr_update->execute();
			$sqr_update->finish();
		}
	}
	else
	{
		$sqr_select = $dbh->prepare("select enable from snmp_check_process where device_ip = '$device_ip' and process = '$name'");
		$sqr_select->execute();
		$ref_select = $sqr_select->fetchrow_hashref();
		my $enable = $ref_select->{"enable"};
		$sqr_select->finish();

		if($enable == 1)
		{
			my $sqr_update = $dbh->prepare("update snmp_check_process set process_status = $val, datetime = '$cur_time' where device_ip = '$device_ip' and process = '$name'");
			$sqr_update->execute();
			$sqr_update->finish();
		}
		else
		{
			my $sqr_update = $dbh->prepare("update snmp_check_process set process_status = null, datetime = null where device_ip = '$device_ip' and process = '$name'");
			$sqr_update->execute();
			$sqr_update->finish();
		}
	}
}

sub insert_into_port
{
	my($dbh,$device_ip,$port,$val,$cur_time) = @_;

	unless(defined $port)
	{
		my $sqr_update = $dbh->prepare("update snmp_check_port set port_status = $val, datetime = '$cur_time' where device_ip = '$device_ip'");
		$sqr_update->execute();
		$sqr_update->finish();
		return;
	}

	my $sqr_select = $dbh->prepare("select count(*) from snmp_check_port where device_ip = '$device_ip' and port = $port");
	$sqr_select->execute();
	my $ref_select = $sqr_select->fetchrow_hashref();
	my $device_num = $ref_select->{"count(*)"};
	$sqr_select->finish();

	if($device_num == 0)
	{
		my $sqr_insert = $dbh->prepare("insert into snmp_check_port (device_ip,port) values ('$device_ip',$port)");
		$sqr_insert->execute();
		$sqr_insert->finish();

		$sqr_select = $dbh->prepare("select enable from snmp_check_port where device_ip = '$device_ip' and port = $port");
		$sqr_select->execute();
		$ref_select = $sqr_select->fetchrow_hashref();
		my $enable = $ref_select->{"enable"};
		$sqr_select->finish();

		if($enable != 1)
		{
			if($debug == 1)
			{
				my $sqr_update = $dbh->prepare("update snmp_check_port set enable = 1 where device_ip = '$device_ip' and port = $port");
				$sqr_update->execute();
				$sqr_update->finish();

				$sqr_update = $dbh->prepare("update snmp_check_port set port_status = $val, datetime = '$cur_time' where device_ip = '$device_ip' and port = $port");
				$sqr_update->execute();
				$sqr_update->finish();
			}
		}
		else
		{
			my $sqr_update = $dbh->prepare("update snmp_check_port set port_status = $val, datetime = '$cur_time' where device_ip = '$device_ip' and port = $port");
			$sqr_update->execute();
			$sqr_update->finish();
		}
	}
	else
	{
		$sqr_select = $dbh->prepare("select enable from snmp_check_port where device_ip = '$device_ip' and port = $port");
		$sqr_select->execute();
		$ref_select = $sqr_select->fetchrow_hashref();
		my $enable = $ref_select->{"enable"};
		$sqr_select->finish();

		if($enable == 1)
		{
			my $sqr_update = $dbh->prepare("update snmp_check_port set port_status = $val, datetime = '$cur_time' where device_ip = '$device_ip' and port = $port");
			$sqr_update->execute();
			$sqr_update->finish();
		}
		else
		{
			my $sqr_update = $dbh->prepare("update snmp_check_port set port_status = null, datetime = null where device_ip = '$device_ip' and port = $port");
			$sqr_update->execute();
			$sqr_update->finish();
		}
	}
}

sub warning_func
{
	my($dbh,$cur_time,$monitor,$device_ip,$cur_val,$type,$disk) = @_;
	my $status;
	my $alarm_status = -1;
	my $out_interval = 0;				#是否超过时间间隔

	if($cur_val < 0)
	{
		$status = 0;
		my $sqr_select = $dbh->prepare("select max(alarm) from snmp_status where device_ip = '$device_ip'");
		$sqr_select->execute();
		my $ref_select = $sqr_select->fetchrow_hashref();
		my $alarm = $ref_select->{"max(alarm)"};
		$sqr_select->finish();

		unless(defined $alarm) 
		{
			$alarm = 0;
		}

		$sqr_select = $dbh->prepare("select unix_timestamp(last_sendtime),send_interval from snmp_status where device_ip = '$device_ip'");
		$sqr_select->execute();
		while($ref_select = $sqr_select->fetchrow_hashref())
		{
			my $last_sendtime = $ref_select->{"unix_timestamp(last_sendtime)"};
			my $send_interval = $ref_select->{"send_interval"};

			unless(defined $last_sendtime)
			{
				$out_interval = 1;
				last;
			}
			elsif(($time_now_utc - $last_sendtime) > ($send_interval * 60))
			{
				$out_interval = 1;
				last;
			}

		}
		$sqr_select->finish();

		if($alarm == 1)
		{
			if($out_interval == 1)
			{
				$alarm_status = -1;
			}
			else
			{
				$alarm_status = 3;
			}
		}
		elsif($alarm == 0)
		{
			$alarm_status = 0;
		}

		my $sqr_insert = $dbh->prepare("insert into snmp_status_warning_log (device_ip,datetime,mail_status,monitor,cur_val,context) values ('$device_ip','$cur_time',$alarm_status,'$monitor',-100,'无法得到值')");
		$sqr_insert->execute();
		$sqr_insert->finish();
		return $status;
	}

	unless(defined $disk)
	{
		my $sqr_select = $dbh->prepare("select alarm,highvalue,lowvalue,unix_timestamp(last_sendtime),send_interval from snmp_status where device_ip = '$device_ip' and type = '$type'");
		$sqr_select->execute();
		my $ref_select = $sqr_select->fetchrow_hashref();
		my $alarm = $ref_select->{"alarm"};
		my $highvalue = $ref_select->{"highvalue"};
		my $lowvalue = $ref_select->{"lowvalue"};
		my $last_sendtime = $ref_select->{"unix_timestamp(last_sendtime)"};
		my $send_interval = $ref_select->{"send_interval"};
		$sqr_select->finish();

		unless(defined $alarm) 
		{
			$alarm = 0;
		}

		unless(defined $last_sendtime)
		{
			$out_interval = 1;
		}
		elsif(($time_now_utc - $last_sendtime) > ($send_interval * 60))
		{
			$out_interval = 1;
		}

		if($alarm == 1)
		{
			if($out_interval == 1)
			{
				$alarm_status = -1;
			}
			else
			{
				$alarm_status = 3;
			}
		}
		elsif($alarm == 0)
		{
			$alarm_status = 0;
		}

		if(defined $highvalue && defined $lowvalue && ($cur_val > $highvalue || $cur_val < $lowvalue))
		{
			$status = 2;
			my $thold;

			my $tmp_context = "";
			if($cur_val > $highvalue)
			{
				$thold = $highvalue;
				$tmp_context = "大于最大值 $highvalue";
			}
			else
			{
				$thold = $lowvalue;
				$tmp_context = "小于最小值 $lowvalue";
			}

			my $sqr_insert = $dbh->prepare("insert into snmp_status_warning_log (device_ip,datetime,mail_status,monitor,type,cur_val,thold,context) values ('$device_ip','$cur_time',$alarm_status,'$monitor','$type',$cur_val,$thold,'$type 超值, 当前值 $cur_val $tmp_context')");
			$sqr_insert->execute();
			$sqr_insert->finish();
		}
		else
		{
			$status = 1;
		}

		return $status;
	}

	if(defined $disk)
	{
		$disk =~ s/\\/\\\\/g;
	}

	my $sqr_select = $dbh->prepare("select alarm,highvalue,lowvalue,unix_timestamp(last_sendtime),send_interval from snmp_status where device_ip = '$device_ip' and type = 'disk' and disk = '$disk'");
	$sqr_select->execute();
	my $ref_select = $sqr_select->fetchrow_hashref();
	my $alarm = $ref_select->{"alarm"};
	my $highvalue = $ref_select->{"highvalue"};
	my $lowvalue = $ref_select->{"lowvalue"};
	my $last_sendtime = $ref_select->{"unix_timestamp(last_sendtime)"};
	my $send_interval = $ref_select->{"send_interval"};
	$sqr_select->finish();

	unless(defined $alarm) 
	{
		$alarm = 0;
	}

	unless(defined $last_sendtime)
	{
		$out_interval = 1;
	}
	elsif(($time_now_utc - $last_sendtime) > ($send_interval * 60))
	{
		$out_interval = 1;
	}

	if($alarm == 1)
	{
		if($out_interval == 1)
		{
			$alarm_status = -1;
		}
		else
		{
			$alarm_status = 3;
		}
	}
	elsif($alarm == 0)
	{
		$alarm_status = 0;
	}

	if(defined $highvalue && defined $lowvalue && ($cur_val > $highvalue || $cur_val < $lowvalue))
	{
		$status = 2;
		my $thold;

		my $tmp_context = "";
		if($cur_val > $highvalue)
		{
			$thold = $highvalue;
			$tmp_context = "大于最大值 $highvalue";
		}
		else
		{
			$thold = $lowvalue;
			$tmp_context = "小于最小值 $lowvalue";
		}

		my $sqr_insert = $dbh->prepare("insert into snmp_status_warning_log (device_ip,datetime,mail_status,monitor,type,cur_val,thold,disk,context) values ('$device_ip','$cur_time',$alarm_status,'$monitor','$type',$cur_val,$thold,'$disk','$type: $disk 超值, 当前值 $cur_val $tmp_context')");
		$sqr_insert->execute();
		$sqr_insert->finish();
	}
	else
	{
		$status = 1;
	}

	return $status;
}

sub update_rrd
{
	my($dbh,$device_ip,$type_name,$value,$disk,$start_time) = @_;

	my $enable;
	my $rrdfile;

	if(defined $disk)
	{
		$disk =~ s/\\/\\\\/g;
		my $sqr_select = $dbh->prepare("select enable,rrdfile from snmp_status where device_ip = '$device_ip' and type = 'disk' and disk = '$disk'");
		$sqr_select->execute();
		my $ref_select = $sqr_select->fetchrow_hashref();
		$enable = $ref_select->{"enable"};
		$rrdfile = $ref_select->{"rrdfile"};
		$sqr_select->finish();
	}
	else
	{
		my $sqr_select = $dbh->prepare("select enable,rrdfile from snmp_status where device_ip = '$device_ip' and type = '$type_name'");
		$sqr_select->execute();
		my $ref_select = $sqr_select->fetchrow_hashref();
		$enable = $ref_select->{"enable"};
		$rrdfile = $ref_select->{"rrdfile"};
		$sqr_select->finish();
	}

	unless(defined $enable && $enable == 1) {return;}

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

	my $file = $dir."/$type_name.rrd";
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

	unless(defined $rrdfile && $rrdfile eq $file) 
	{
		my $sqr_update;
		if(defined $disk)
		{
			$sqr_update = $dbh->prepare("update snmp_status set rrdfile = '$file' where device_ip = '$device_ip' and type = 'disk' and disk = '$disk'");
		}
		else
		{
			$sqr_update = $dbh->prepare("update snmp_status set rrdfile = '$file' where device_ip = '$device_ip' and type = '$type_name'");
		}
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
			'--', join(':', "$start_time", "$value"), 
			); 
}

sub update_rrd_process
{
	my($dbh,$device_ip,$name,$value,$start_time) = @_;

	my $sqr_select = $dbh->prepare("select enable,rrdfile from snmp_check_process where device_ip = '$device_ip' and process = '$name'");
	$sqr_select->execute();
	my $ref_select = $sqr_select->fetchrow_hashref();
	my $enable = $ref_select->{"enable"};
	my $rrdfile = $ref_select->{"rrdfile"};
	$sqr_select->finish();
	
	unless(defined $enable && $enable == 1) {return;}

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

	$dir = "/opt/freesvr/nm/$device_ip/process_status";
	if(! -e $dir)
	{
		mkdir $dir,0755;
	}

	my $file = $dir."/$name.rrd";
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

	unless(defined $rrdfile && $rrdfile eq $file) 
	{
		my $sqr_update = $dbh->prepare("update snmp_check_process set rrdfile = '$file' where device_ip = '$device_ip' and process = '$name'");
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
			'--', join(':', "$start_time", "$value"), 
			); 
}

sub update_rrd_port
{
	my($dbh,$device_ip,$port,$value,$start_time) = @_;

	my $sqr_select = $dbh->prepare("select enable,rrdfile from snmp_check_port where device_ip = '$device_ip' and port = $port");
	$sqr_select->execute();
	my $ref_select = $sqr_select->fetchrow_hashref();
	my $enable = $ref_select->{"enable"};
	my $rrdfile = $ref_select->{"rrdfile"};
	$sqr_select->finish();
	
	unless(defined $enable && $enable == 1) {return;}

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

	$dir = "/opt/freesvr/nm/$device_ip/port_status";
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
	}

	unless(defined $rrdfile && $rrdfile eq $file) 
	{
		my $sqr_update = $dbh->prepare("update snmp_check_port set rrdfile = '$file' where device_ip = '$device_ip' and port = $port");
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
			'--', join(':', "$start_time", "$value"), 
			); 
}

sub alarm_process
{
	my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});

	my $utf8 = $dbh->prepare("set names utf8");
	$utf8->execute();
	$utf8->finish();

	my $sqr_select = $dbh->prepare("select monitor,device_type from servers where device_ip = '$host' and monitor!=0");
	$sqr_select->execute();
	my $ref_select = $sqr_select->fetchrow_hashref();
	my $monitor = $ref_select->{"monitor"};
	my $device_type = $ref_select->{"device_type"};
	$sqr_select->finish();

	my $only_cpu_mem = 0;
	if($device_type == 11)
	{
		$only_cpu_mem = 1;
	}

	if(!defined $monitor)
	{
		$monitor = "";
	}
	elsif($monitor == 1)
	{
		$monitor = "snmp";
	}
	elsif($monitor == 2)
	{
		$monitor = "ssh";
	}
	elsif($monitor == 3)
	{
		$monitor = "读文件";
	}

	&err_process($dbh,$monitor,$host,1,"程序超时",$time_now_str,$only_cpu_mem,undef); 
	exit;
}
