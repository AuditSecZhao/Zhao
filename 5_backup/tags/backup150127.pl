#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use DBD::mysql;
use Expect;
use POSIX ":sys_wait_h"; 

our $debug = 1;
$SIG{ALRM}=\&alarm_process;
our $process_time = 7200;
our $cur_host;
our @backup_ip;
our $time_now_utc = time;
my($min,$hour,$mday,$mon,$year) = (localtime $time_now_utc)[1..5];
($min,$hour,$mday,$mon,$year) = (sprintf("%02d", $min),sprintf("%02d", $hour),sprintf("%02d", $mday),sprintf("%02d", $mon + 1),$year+1900);
our $time_now_str = "$year$mon$mday$hour$min"."00";

if(-e "/tmp/audit_sec_backup.sql")
{
	unlink "/tmp/audit_sec_backup.sql";
}

&read_mysql();
foreach my $ref(@backup_ip)
{
	$cur_host = $ref->[0];
	alarm($process_time);
	&backup(@$ref);
	alarm(0);
}

exit 0;

sub read_mysql
{
	my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});
	my $utf8 = $dbh->prepare("set names utf8");
	$utf8->execute();
	$utf8->finish();

	my $sqr_select = $dbh->prepare("select ip,port,dbactive,fileactive,user,udf_decrypt(passwd),mysqluser,udf_decrypt(mysqlpasswd),path,dbname,protocol from backup_setting where (dbactive=1 or fileactive=1) and session_flag=0");
	$sqr_select->execute(); 
	while(my $ref = $sqr_select->fetchrow_hashref())
	{                   
		my $ip = $ref->{"ip"};
		my $port = $ref->{"port"};
		my $dbactive = $ref->{"dbactive"};
		my $fileactive = $ref->{"fileactive"};
		my $user = $ref->{"user"};
		my $passwd = $ref->{"udf_decrypt(passwd)"};
		my $mysqluser = $ref->{"mysqluser"};
		my $mysqlpasswd = $ref->{"udf_decrypt(mysqlpasswd)"};
		my $path_prefix = $ref->{"path"};
		my $dbname = $ref->{"dbname"};
        my $protocol = $ref->{"protocol"};

		$path_prefix =~ s/\/$//;				#去掉 path 前缀最后的 /
		my @temp = ($ip,$port,$dbactive,$fileactive,$user,$passwd,$mysqluser,$mysqlpasswd,$path_prefix,$dbname,$protocol);
		push @backup_ip,\@temp;
	}           
	$sqr_select->finish();
	$dbh->disconnect();
}

sub trans_dir
{
	my($last_date,$work_dir) = @_;
	opendir(my $dir_handle,".");
	my @dirs;

	my($now_day,$now_mon,$now_year) = (localtime)[3..5];
	$now_mon += 1;
	$now_year += 1900;

	if(defined $last_date)
	{
		$last_date =~ /(\d+)-(\d+)-(\d+)/;
		my $year = int($1);
		my $mon = int($2);
		my $day = int($3);

		while(my $dir = readdir($dir_handle)) 
		{
			if($dir =~ /(\d+)-(\d+)-(\d+)/)
			{
				if((int($1) == $now_year) && (int($2) == $now_mon) && (int($3) == $now_day)){next;}

				if(int($1) > $year)
				{
					push @dirs,"$dir";
				}
				elsif((int($1) == $year) && (int($2) > $mon))
				{
					push @dirs,"$dir";
				}
				elsif((int($1) == $year) && (int($2) == $mon) && (int($3) >= $day))
				{
					push @dirs,"$dir";
				}
			}
		}
	}
	else
	{
		while(my $dir = readdir($dir_handle)) 
		{
			if($dir =~ /(\d+)-(\d+)-(\d+)/)
			{
				if((int($1) == $now_year) && (int($2) == $now_mon) && (int($3) == $now_day)){next;}

				push @dirs,"$dir";
			}
		}

	}
	return @dirs;
}

sub scp_file
{
	my($dbh,$cmd,$passwd,$device_ip,$dir) = @_;

	my $exp = Expect->new;
	$exp->log_stdout(0);
	$exp->spawn($cmd);
	$exp->debug(0);
	my $pid = $exp->pid();
	if($debug == 1)
	{
		print $cmd,"\n";
	}

	my @results = $exp->expect(10,[
			qr/password/i,
			sub {
			my $self = shift ;
			$self->send_slow(0.1,"$passwd\n");
			}
			],
			[
			qr/yes/i,
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
			&err_process($dbh,$device_ip,$results[1]);
			if($debug == 1)
			{
				print "主机 $device_ip 其他错误退出\n";
			}
			return 2;
		}

		my $output = $exp->before();
		my @context = split /\n/,$output;

		if($errno == 1)
		{
			&err_process($dbh,$device_ip,'scp cmd timeout');
			if($debug == 1)
			{
				print "主机 $device_ip scp命令超时\n";
			}
			return 2;
		}
		elsif($errno == 3)
		{
			foreach my $line(@context)
			{
				if($line =~ /No\s*route\s*to\s*host/i)
				{
					&err_process($dbh,$device_ip,"no route to dst host:$device_ip");
					if($debug == 1)
					{
						print "主机 $device_ip no route to dst host\n";
					}
					return 2;
				}

				if($line =~ /Connection\s*refused/i)
				{
					&err_process($dbh,$device_ip,"connection refused by dst host:$device_ip, maybe sshd is closed");
					if($debug == 1)
					{
						print "主机 $device_ip connection refused, maybe sshd is closed\n";
					}
					return 2;
				}

				if($line =~ /Host\s*key\s*verification\s*failed/i)
				{
					&err_process($dbh,$device_ip,"Host key verification failed:$device_ip");
					if($debug == 1)
					{
						print "主机 $device_ip Host key verification failed\n";
					}
					return 2;
				}
			}
		}
		else
		{
			&err_process($dbh,$device_ip,$results[1]);
			if($debug == 1)
			{
				print "主机 $device_ip 其他错误退出\n";
			}
			return 2;
		}
	}

	sleep 2;
	my $child_pid = waitpid($pid,WNOHANG);
	if($child_pid != 0)
	{
		return (WEXITSTATUS($?)==0 ? 1 : 2);
	}

	$exp->expect(1, undef);
	my $output = $exp->before();

	foreach my $line(split /\n/,$output)
	{
		if($line =~ /No\s*such\s*file\s*or\s*directory/i)
		{
			&err_process($dbh,$device_ip,"路径不存在 $dir");
			if($debug == 1)
			{
				print "主机 $device_ip 路径不存在 $dir\n";
			} 
			return 2;
		}
		if($line =~ /password/i)
		{
			&err_process($dbh,$device_ip,"passwd for $device_ip is wrong");
			if($debug == 1)
			{
				print "主机 $device_ip passwd is wrong\n";
			}
			return 2;
		}
	}

	$child_pid = waitpid($pid,0);
	return (WEXITSTATUS($?)==0 ? 1 : 2);
}

sub backup
{
	my($ip,$port,$dbactive,$fileactive,$user,$passwd,$mysqluser,$mysqlpasswd,$path_prefix,$dbname,$protocol) = @_;
	my $file_status = 0;
	my $db_status = 0;
	my $last_date;

	my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});
	my $utf8 = $dbh->prepare("set names utf8");
	$utf8->execute();
	$utf8->finish();

	my $sqr_insert = $dbh->prepare("insert into backup_log(ip,starttime) values('$ip',now())");
	$sqr_insert->execute();
	$sqr_insert->finish();

	if($fileactive != 0)
	{
		my @work_dirs = qw#/opt/freesvr/audit/gateway/log/db2
			/opt/freesvr/audit/gateway/log/mysql
			/opt/freesvr/audit/gateway/log/oracle
			/opt/freesvr/audit/gateway/log/sybase
			/opt/freesvr/audit/gateway/log/sqlserver
			/opt/freesvr/audit/gateway/log/telnet/cache
			/opt/freesvr/audit/gateway/log/telnet/replay
			/opt/freesvr/audit/gateway/log/ssh/cache
			/opt/freesvr/audit/gateway/log/ssh/replay
			/opt/freesvr/audit/gateway/log/rdp/replay
			/opt/freesvr/audit/gateway/log/rdp/key#;

		my $sqr_select = $dbh->prepare("select max(date(starttime)) from backup_log where filelog=1 and ip='$ip'");
		$sqr_select->execute();
		my $ref = $sqr_select->fetchrow_hashref();
		if(defined $ref->{"max(date(starttime))"})
		{
			$last_date = $ref->{"max(date(starttime))"};
		}
		$sqr_select->finish();

		foreach my $work_dir(@work_dirs)
		{
			$work_dir .= "/";
			chdir $work_dir;
			my @temp_dir = &trans_dir($last_date,$work_dir);
			if(scalar @temp_dir != 0)
			{
				my $cmd = "scp -P $port -q -r ".join(" ",@temp_dir)." $user\@$ip:$path_prefix$work_dir";
				$file_status = &scp_file($dbh,$cmd,$passwd,$ip,"$path_prefix$work_dir");

				if($file_status == 2)
				{
					my $sqr_update = $dbh->prepare("update backup_log set filelog = 2 where ip = '$ip' and endtime is null");
					$sqr_update->execute();
					$sqr_update->finish();
				}
			}
		}

		$sqr_select = $dbh->prepare("select filelog from backup_log where ip='$ip' and endtime is null");
		$sqr_select->execute();
		$ref = $sqr_select->fetchrow_hashref();
		if(!defined $ref->{"filelog"})
		{
			my $sqr_update = $dbh->prepare("update backup_log set filelog=$file_status where ip='$ip' and endtime is null");
			$sqr_update->execute();
			$sqr_update->finish();
		}
		$sqr_select->finish();
	}
	else
	{
		my $sqr_update = $dbh->prepare("update backup_log set filelog=0 where ip='$ip' and endtime is null");
		$sqr_update->execute();
		$sqr_update->finish();
	}

	if($dbactive == 1 || $dbactive == 2)
	{
		my $cmd;
		if($dbactive == 1)
		{
			$cmd = "mysqldump -h localhost -u root audit_sec>/tmp/audit_sec_backup.sql";
		}
		else
		{
			my @tables = qw/
				ac_group                  
				ac_network                
				admin_log                 
				alarm                     
				alert_mailsms             
				appdevices                
				appgroup                  
				appmember                 
				appprogram                
				apppserver                
				apppub                    
				appresourcegroup          
				appurl                    
				dangerscmds               
				defaultpolicy             
				dev                       
				device                    
				device_html               
				device_oid                
				devices                   
				devices_password          
				forbidden_commands        
				forbidden_commands_groups 
				forbidden_commands_user   
				forbidden_groups  
				http_process              
				http_process_alarm        
				ip                        
				ldap                      
				ldapdevice                
				ldapmanager               
				ldapuser                  
				lgroup                    
				lgroup_appresourcegrp     
				lgroup_devgrp             
				lgroup_resourcegrp        
				login_tab                 
				login_template            
				loginacctcode             
				luser                     
				luser_appresourcegrp      
				luser_devgrp              
				luser_resourcegrp         
				member                    
				password_cache            
				password_policy           
				password_rules            
				passwordkey               
				prompts                   
				proxyip                   
				radcheck                  
				radgroupcheck             
				radgroupreply             
				radhuntcheck              
				radhuntgroup              
				radhuntgroupcheck         
				radhuntreply              
				radkey                    
				radreply                  
				radsourcecheck            
				radsourcegroup            
				radsourcegroupcheck       
				radsourcereply            
				radwmkey                  
				random                    
				rdptoapp                  
				resourcegroup             
				restrictacl               
				restrictpolicy            
				servergroup               
				servers                   
				setting                   
				sourceip                  
				sourceiplist              
				sshkey                    
				sshkeyname                
				sshprivatekey             
				sshpublickey              
				strategy                  
				weektime 
				/;

			$cmd = "mysqldump -h localhost -u root audit_sec ".join(" ",@tables)." >/tmp/audit_sec_backup.sql";
		}

		unless(-e "/tmp/audit_sec_backup.sql")
		{
			if($debug == 1)
			{
				print $cmd,"\n";
			}

			$db_status = system($cmd);
			$db_status = ($db_status == 0) ? 1 : 2;
			if($db_status == 2)
			{
				&err_process($dbh,$ip,"主机 mysqldump数据库 $dbname 错误");
				if($debug == 1)
				{
					print "主机 $ip mysqldump数据库 $dbname 错误\n";
				}

				my $sqr_update = $dbh->prepare("update backup_log set dblog = 2 where ip = '$ip' and endtime is null");
				$sqr_update->execute();
				$sqr_update->finish();
				unlink "/tmp/audit_sec_backup.sql";
				if($debug == 1)
				{
					print "主机 $ip 删除 audit_sec_backup.sql\n";
				}
			}
		}

		my $sqr_select = $dbh->prepare("select dblog from backup_log where ip='$ip' and endtime is null");
		$sqr_select->execute();
		my $ref = $sqr_select->fetchrow_hashref();
		if(!defined $ref->{"dblog"})
		{
			$cmd = "mysql -h $ip -u $mysqluser ";
			if(defined $mysqlpasswd)
			{
				$cmd .= "-p$mysqlpasswd ";
			}
			$cmd .= "audit_sec</tmp/audit_sec_backup.sql";
			if($debug == 1)
			{
				print $cmd,"\n";
			}
			$db_status = system($cmd);
			$db_status = ($db_status == 0) ? 1 : 2;

			if($db_status == 2)
			{
				&err_process($dbh,$ip,"主机 备份数据库 $dbname 错误");
				if($debug == 1)
				{
					print "主机 $ip 备份数据库 $dbname 错误\n";
				}
			}

			my $sqr_update = $dbh->prepare("update backup_log set dblog = $db_status where ip = '$ip' and endtime is null");
			$sqr_update->execute();
			$sqr_update->finish();

			unlink "/tmp/audit_sec_backup.sql";
			if($debug == 1)
			{
				print "主机 $ip 删除 audit_sec_backup.sql\n";
			}
		}
	}
	else
	{
		my $sqr_update = $dbh->prepare("update backup_log set dblog = 0 where ip = '$ip' and endtime is null");
		$sqr_update->execute();
		$sqr_update->finish();
	}

	my $sqr_update = $dbh->prepare("update backup_log set endtime = now() where ip = '$ip' and endtime is null");
	$sqr_update->execute();
	$sqr_update->finish();

	$dbh->disconnect();
}

sub alarm_process
{       
	my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});

	my $utf8 = $dbh->prepare("set names utf8");
	$utf8->execute();
	$utf8->finish();

	&err_process($dbh,$cur_host,"程序超时");
	$dbh->disconnect();
	exit;
}

sub err_process
{
	my($dbh,$host,$err_str) = @_;

	my $insert = $dbh->prepare("insert into backup_err_log(datetime,host,reason) values('$time_now_str','$host','$err_str')");
	$insert->execute();
	$insert->finish();
}
