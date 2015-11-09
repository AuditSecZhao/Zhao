#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use DBD::mysql;
use File::Pid;

our $pidfile = File::Pid->new({file => '/tmp/linux_login.pid',});
if (my $num = $pidfile->running)
{
	exit;
}
else
{
	$pidfile->remove;
	$pidfile = File::Pid->new({file => '/tmp/linux_login.pid',});
	$pidfile->write;
}

our $log_srever = '1.1.1.1';
our $expire_time = 3600;
our $is_cross_login;
our %right_login_ips;

&read_log_conf();

our $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});
our $utf8 = $dbh->prepare("set names utf8");
$utf8->execute();
$utf8->finish();

open(our $fd_fr,"</var/log/mem/linux.log") or die $!;
#open(our $fd_fr,"<linux.log") or die $!;

while(my $log = <$fd_fr>)
{
	chomp $log;
	my @unit_temp = split  /\|\|/,$log;
	my($log_host,$log_facility,$log_priority,$log_level,$log_tag,$log_datetime,$log_program,$log_msg);
	if(scalar @unit_temp == 8)
	{
		($log_host,$log_facility,$log_priority,$log_level,$log_tag,$log_datetime,$log_program,$log_msg) = @unit_temp;
	}
	else
	{
		($log_host,$log_facility,$log_priority,$log_level,$log_tag,$log_datetime,$log_program,$log_msg) = @unit_temp[0..6];
		$log_msg = join("||",@unit_temp[7..((scalar @unit_temp)-1)]);

	}

	unless(defined $log_program || defined $log_msg){next;}
	unless($log_priority eq "info" || $log_priority eq "notice"){next;}

	if($log_program eq "su")
	{
		my $su_insert;
		if($log_msg =~ /authentication\s+failure/)
		{
			$su_insert = $dbh->prepare("insert into log_eventlogs (host, facility, priority, level, tag, datetime, program,msg,logserver,msg_level,event) values ('$log_host','$log_facility','$log_priority','$log_level','$log_tag','$log_datetime','$log_program','$log_msg','$log_srever',3,'sudo 错误')");
			$su_insert->execute();
			$su_insert->finish();
			next;
		}
		if($log_msg =~ /pam_unix\(su-l:session\):\s+session\s+opened\s+for\s+user/)
		{
			$su_insert = $dbh->prepare("insert into log_eventlogs (host, facility, priority, level, tag, datetime, program,msg,logserver,msg_level,event) values ('$log_host','$log_facility','$log_priority','$log_level','$log_tag','$log_datetime','$log_program','$log_msg','$log_srever',1,'sudo 成功')");
			$su_insert->execute();
			$su_insert->finish();
			next;
		}

	}

	if(defined $is_cross_login && $is_cross_login == 1 && !exists $right_login_ips{$log_host})
	{
		&cross_insert($log_host,$log_facility,$log_priority,$log_level,$log_tag,$log_datetime,$log_program,$log_msg);
	}

	if($log_program eq "sshd")
	{
		my $pid;
		if($log_msg =~  /sshd\s*\[(.*?)\]/){$pid = $1;}

		if($log_msg =~  /sftp/i)
		{
			&sftp_process($log_host,$log_program,$log_msg,$log_datetime,$pid);
			next;
		}

		if($log_msg =~ /accept/i)
		{
			&accept_process($log_host,$log_program,$log_msg,$log_datetime,$pid);
			next;
		}

		if($log_msg =~ /failed password/i)
		{
			&sshfail_process($log_host,$log_program,$log_msg,$log_datetime,$pid);
			next;
		}

		if($log_msg =~ /\bdisconnect\b/i)
		{
			&sshdisconnect_process($log_host,$log_program,$log_msg,$log_datetime,$pid);
			next;
		}

		if($log_msg =~ /pam_unix/i)
		{
			if($log_msg =~ /opened/i)
			{
				my $uid;
				if($log_msg =~ /.*uid\s*=(\d+)/i){$uid = $1;}
				my $sqr_update = $dbh->prepare("update log_linux_login set uid=$uid where uid is NULL and host='$log_host' and pid=$pid and UNIX_TIMESTAMP(starttime)<=UNIX_TIMESTAMP('$log_datetime')");
				$sqr_update->execute();
				$sqr_update->finish();
				next;
			}

			if($log_msg =~ /closed/i)
			{
				my $sqr_update = $dbh->prepare("update log_linux_login set endtime='$log_datetime' where endtime is NULL and host='$log_host' and pid=$pid and uid is not null and UNIX_TIMESTAMP(starttime)<=UNIX_TIMESTAMP('$log_datetime')");
				$sqr_update->execute();
				$sqr_update->finish();
				next;
			}
		}
	}

	if($log_program eq "login")
	{
		if(($log_msg =~ /pam_unix\(login:auth\)/i) && ($log_msg =~ /failure/i))
		{
			&loginfail_process($log_host,$log_program,$log_msg,$log_datetime);
			next;
		}

		if($log_msg =~ /LOGIN ON/i)
		{
			&logon_process($log_host,$log_program,$log_msg,$log_datetime);
			next;
		}

		if(($log_msg =~ /pam_unix\(login:session\)/i) && ($log_msg =~ /closed/i))
		{
			my $user;
			if($log_msg =~ /user\s+(\S+)/i){$user = $1;}

			my $sqr_update = $dbh->prepare("update log_linux_login set endtime='$log_datetime' where endtime is NULL and host='$log_host' and user='$user' and UNIX_TIMESTAMP(starttime)<=UNIX_TIMESTAMP('$log_datetime')");
			$sqr_update->execute();
			$sqr_update->finish();
		}
	}
}

my $sqr_exipre = $dbh->prepare("update log_linux_login set endtime = from_unixtime(UNIX_TIMESTAMP(starttime)+$expire_time) where endtime is null and unix_timestamp()-UNIX_TIMESTAMP(starttime)>$expire_time");
$sqr_exipre->execute();
$sqr_exipre->finish();

close($fd_fr);
open(our $fd_fw,">/var/log/mem/linux.log") or die $!;
close($fd_fw);
$pidfile->remove;

sub read_log_conf
{
    open(my $fd_config,"</home/wuxiaolong/2_syslog/log.conf") or die $!;
    while(my $line = <$fd_config>)
    {
        chomp $line;
        my($name,$value) = split /=/,$line;

        unless(defined $name && defined $value){next;}
        $name =~ s/\s+//g;
        $value =~ s/\s+//g;

        if($name eq "cross_login")
        {
            $is_cross_login = $value;
        }
        if($name eq "login_ip")
        {
            my @tmp_right_login_ips = split /;/,$value;
            foreach(@tmp_right_login_ips)
            {
                $_ =~ s/\s+//g;
                $right_login_ips{$_} = 1;
            }
        }
    }
}

sub cross_insert
{
	my($host,$facility,$priority,$level,$tag,$datetime,$program,$msg) = @_;
	my $sqr_insert = $dbh->prepare("insert into log_eventlogs (host, facility, priority, level, tag, datetime, program,msg,logserver,msg_level,event) values ('$host','$facility','$priority','$level','$tag','$datetime','$program','$msg','$log_srever',3,'跨权登录')");
	$sqr_insert->execute();
	$sqr_insert->finish();
}

sub accept_process
{
	my($host,$program,$msg,$datetime,$pid) = @_;
	my $srcip;my $port;my $user;my $protocol;my $mod;
	if($msg =~ /password/i){$mod = "password";}
	if($msg =~ /publickey/i){$mod = "publickey";}
	if($msg =~ /for\s*(.*)\sfrom\s*(\d+\.\d+\.\d+\.\d+).*port\s*(\d+).*\s+(.+)$/i)
	{
		$user = $1;$srcip = $2;$port = $3;$protocol = $4;
	}
	my $sqr_insert = $dbh->prepare("insert into log_linux_login (starttime,login_mod,pid,host,port,srchost,protocol,active,user,msg,logserver) values ('$datetime','$program-$mod',$pid,'$host',$port,'$srcip','$protocol',1,'$user','$msg','$log_srever')");
	$sqr_insert->execute();
	$sqr_insert->finish();
}

sub sftp_process
{
	my($host,$program,$msg,$datetime,$pid) = @_;
	my $sqr_select = $dbh->prepare("select login_mod,port,srchost,active,user,uid from log_linux_login where host='$host' and pid=$pid");
	$sqr_select->execute();
	my $ref_select = $sqr_select->fetchrow_hashref();
	my $login_mod = $ref_select->{"login_mod"};
	my $port = $ref_select->{"port"};
	my $srchost = $ref_select->{"srchost"};
	my $active = $ref_select->{"active"};
	my $user = $ref_select->{"user"};
	my $uid = $ref_select->{"uid"};

	$sqr_select->finish();
	unless(defined $srchost && defined $port && defined $user && defined $uid){return;}

	my $sqr_insert = $dbh->prepare("insert into log_linux_login (starttime,login_mod,pid,host,port,srchost,protocol,active,user,msg,logserver,uid) values ('$datetime','$login_mod',$pid,'$host',$port,'$srchost','sftp',1,'$user','$msg','$log_srever',$uid)");
	$sqr_insert->execute();
	$sqr_insert->finish();
}

sub sshfail_process
{
	my($host,$program,$msg,$datetime,$pid) = @_;
	my $srcip;my $port;my $user;my $protocol;my $mod="password";

	if($msg =~ /for\s*(.*)\sfrom\s*(\d+\.\d+\.\d+\.\d+).*port\s*(\d+).*\s+(.+)$/i)
	{
		$user = $1;$srcip = $2;$port = $3;$protocol = $4;
	}

	my $sqr_insert = $dbh->prepare("insert into log_linux_login (starttime,endtime,login_mod,pid,host,port,srchost,protocol,active,user,msg,logserver) values ('$datetime','$datetime','$program-$mod',$pid,'$host',$port,'$srcip','$protocol',0,'$user','$msg','$log_srever')");
	$sqr_insert->execute();
	$sqr_insert->finish();
}

sub sshdisconnect_process
{
	my($host,$program,$msg,$datetime,$pid) = @_;
	my $srcip;my $port;my $protocol="ssh2";my $mod="password";

	if($msg =~ /from\s*(\d+\.\d+\.\d+\.\d+).*:\s*(\d+)/i)
	{
		$srcip = $1;$port = $2;
	}

	my $sqr_insert = $dbh->prepare("insert into log_linux_login (starttime,endtime,login_mod,pid,host,port,srchost,protocol,active,msg,logserver) values ('$datetime','$datetime','$program-$mod',$pid,'$host',$port,'$srcip','$protocol',-1,'$msg ','$log_srever')");
	$sqr_insert->execute();
	$sqr_insert->finish();
}

sub loginfail_process
{
	my($host,$program,$msg,$datetime) = @_;
	my $uid;my $user;my $protocol;

	if($msg =~ /uid=(\d+)/i){$uid = $1;}
	if($msg =~ /tty=(\S+)/i){$protocol = $1;}
	if($msg =~ /user=(\S+)/i){$user = $1;}

	my $sqr_insert;
	if(defined $user){$sqr_insert = $dbh->prepare("insert into log_linux_login (starttime,endtime,login_mod,host,protocol,active,msg,logserver,uid,user) values ('$datetime','$datetime','$program','$host','$protocol',0,'$msg','$log_srever',$uid,'$user')");}
	else{$sqr_insert = $dbh->prepare("insert into log_linux_login (starttime,endtime,login_mod,host,protocol,active,msg,logserver,uid) values ('$datetime','$datetime','$program','$host','$protocol',0,'$msg','$log_srever',$uid)");}
	$sqr_insert->execute();
	$sqr_insert->finish();
}

sub logon_process
{
	my($host,$program,$msg,$datetime) = @_;
	my $user;my $protocol;

	if($msg =~ /.*\:\s*(\S+).*\s+(.*)$/i)
	{
		$user = lc($1);
		$protocol = $2;
	}

	my $sqr_update = $dbh->prepare("update log_linux_login set endtime='$datetime' where endtime is NULL and host='$host' and user='$user' and login_mod = 'login' and UNIX_TIMESTAMP(starttime)<=UNIX_TIMESTAMP('$datetime')");
	$sqr_update->execute();
	$sqr_update->finish();

	my $sqr_insert = $dbh->prepare("insert into log_linux_login (starttime,login_mod,host,protocol,active,msg,logserver,user) values ('$datetime','$program','$host','$protocol',1,'$msg','$log_srever','$user')");
	$sqr_insert->execute();
	$sqr_insert->finish();
}
