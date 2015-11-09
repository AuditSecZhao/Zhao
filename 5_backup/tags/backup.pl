#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use DBD::mysql;
use Expect;
use POSIX ":sys_wait_h"; 

our @backup_ip;
&read_mysql();
foreach my $ref(@backup_ip)
{
	&backup(@$ref);
}

my $cmd = "rm -f /tmp/audit_sec_backup.sql";
my $temp = &exec_cmd($cmd,0,0);
exit 0;

sub read_mysql
{
	my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});
	my $utf8 = $dbh->prepare("set names utf8");
	$utf8->execute();
	$utf8->finish();

	my $sqr_select = $dbh->prepare("select ip,port,dbactive,fileactive,user,udf_decrypt(passwd),mysqluser,udf_decrypt(mysqlpasswd) from backup_setting where dbactive!=0 or fileactive!=0");
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

		my @temp = ($ip,$port,$dbactive,$fileactive,$user,$passwd,$mysqluser,$mysqlpasswd);
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

sub exec_cmd
{
	my($cmd,$passwd,$flag) = @_;

	my $exp = Expect->new;
	$exp->log_stdout(0);
	$exp->spawn($cmd);
	my $pid = $exp->pid();

	if($flag == 1)
	{
		$exp->expect(120,[
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
	}

	my $child_pid = waitpid($pid,0);
	return (WEXITSTATUS($?)==0 ? 1 : 2);
}

sub backup
{
	my($ip,$port,$dbactive,$fileactive,$user,$passwd,$mysqluser,$mysqlpasswd) = @_;
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
				my $cmd = "scp -P $port -q -r ".join(" ",@temp_dir)." $user\@$ip:$work_dir";
#				print $cmd,"\n";
				$file_status = &exec_cmd($cmd,$passwd,1);

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
			my $sqr_update = $dbh->prepare("update backup_log set filelog = $file_status where ip = '$ip' and endtime is null");
			$sqr_update->execute();
			$sqr_update->finish();
		}
		$sqr_select->finish();
	}
	else
	{
		my $sqr_update = $dbh->prepare("update backup_log set filelog = 0 where ip = '$ip' and endtime is null");
		$sqr_update->execute();
		$sqr_update->finish();
	}

	if($dbactive != 0)
	{
		my $cmd = "mysqldump -h localhost -u root audit_sec>/tmp/audit_sec_backup.sql";
		unless(-e "/tmp/audit_sec_backup.sql")
		{
			$db_status = &exec_cmd($cmd,0,0);
			if($db_status == 2)
			{
				my $sqr_update = $dbh->prepare("update backup_log set dblog = 2 where ip = '$ip' and endtime is null");
				$sqr_update->execute();
				$sqr_update->finish();
				$cmd = "rm -f /tmp/audit_sec_backup.sql";
				my $temp = &exec_cmd($cmd,0,0);
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
#			print $cmd,"\n";
			$db_status = &exec_cmd($cmd,0,0);

			my $sqr_update = $dbh->prepare("update backup_log set dblog = $db_status where ip = '$ip' and endtime is null");
			$sqr_update->execute();
			$sqr_update->finish();
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
}


