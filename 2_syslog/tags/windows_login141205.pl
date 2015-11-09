#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use DBD::mysql;
use File::Pid;

our $pidfile = File::Pid->new({file => '/tmp/windows_login.pid',});
if (my $num = $pidfile->running)
{
	exit;
}
else    
{       
	$pidfile->remove;
	$pidfile = File::Pid->new({file => '/tmp/windows_login.pid',});
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

#open(our $fd_fr,"<windows.log") or die $!;
open(our $fd_fr,"</var/log/mem/windows.log") or die $!;

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

	if(defined $is_cross_login && $is_cross_login == 1 && !exists $right_login_ips{$log_host})
    {           
        &cross_insert($log_host,$log_facility,$log_priority,$log_level,$log_tag,$log_datetime,$log_program,$log_msg);
    }

	if($log_msg =~ /登录失败/i)
	{
		&loginfail_process($log_host,$log_msg,$log_datetime);
		next;
	}

	if($log_msg =~ /登录成功/i)
	{
		&loginsuccess_process($log_host,$log_msg,$log_datetime);
		next;
	}

	if($log_msg =~ /用户注销/i)
	{
		&logincancel_process($log_host,$log_msg,$log_datetime);
		next;
	}


}

my $sqr_exipre = $dbh->prepare("update log_windows_login set endtime = from_unixtime(UNIX_TIMESTAMP(starttime)+$expire_time) where endtime is null and unix_timestamp()-UNIX_TIMESTAMP(starttime)>$expire_time");
$sqr_exipre->execute();
$sqr_exipre->finish();

close($fd_fr);
open(our $fd_fw,">/var/log/mem/windows.log") or die $!;
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

sub loginfail_process
{
	my($host,$msg,$datetime) = @_;
	my $srcip;my $port;my $user;my $protocol;
	my $sqr_insert;

	if($msg =~ /源网络地址:\s*(\S+)/i)
	{
		if($1 eq "-")
		{
			if($msg =~ /用户名:\s*(\S+).*\s登录进程:\s*(\S+)/i){$user = $1;$protocol = $2;}

			if($user =~ /域/i)
			{
				$sqr_insert = $dbh->prepare("insert into log_windows_login (starttime,endtime,host,protocol,active,msg,logserver) values ('$datetime','$datetime','$host','$protocol',0,'$msg','$log_srever')");
			}
			else
			{
				$sqr_insert = $dbh->prepare("insert into log_windows_login (starttime,endtime,host,protocol,active,user,msg,logserver) values ('$datetime','$datetime','$host','$protocol',0,'$user','$msg','$log_srever')");
			}
		}
		else
		{
			$srcip = $1;
			if($msg =~ /用户名:\s*(\S+).*\s源端口:\s*(\d+)/i){$user = $1;$port = $2;} 

			if($srcip eq "127.0.0.1"){$protocol = "local";}
			else{$protocol = "RDP";}

			if($user =~ /域/i)
			{
				$sqr_insert = $dbh->prepare("insert into log_windows_login (starttime,endtime,host,protocol,active,msg,logserver)values ('$datetime','$datetime','$host','$protocol',0,'$msg','$log_srever')");
			}
			else
			{
				$sqr_insert = $dbh->prepare("insert into log_windows_login (starttime,endtime,host,port,srchost,protocol,active,user,msg,logserver) values ('$datetime','$datetime','$host',$port,'$srcip','$protocol',0,'$user','$msg','$log_srever')");
			}
		}
		$sqr_insert->execute();
		$sqr_insert->finish();
	}
}

sub loginsuccess_process
{
	my($host,$msg,$datetime) = @_;
	my $srcip;my $port;my $user;my $protocol;my $login_id;

#	if($msg =~ /用户名:\s*(\S+).*\s+登录\s*ID:\s+\((\S+)\).*源网络地址:\s*(\d+\.\d+\.\d+\.\d+).*源端口:\s*(\d+)/i)
	if($msg =~ /用户名:\s*(\S+).*\s+登录\s*ID:\s+\((\S+)\).*源网络地址:\s*(\S+)\s+源端口:\s*(\S+)/i)
	{
		$user = $1;$login_id = $2;$srcip = $3;$port = $4;
	}

	if($srcip eq "127.0.0.1"){$protocol = "local";}
	else{$protocol = "RDP";}

	my $sqr_insert;

	if($srcip eq '-' && $port eq '-')
	{
		$sqr_insert = $dbh->prepare("insert into log_windows_login (starttime,login_id,host,protocol,active,user,msg,logserver) values ('$datetime','$login_id','$host','$protocol',1,'$user','$msg','$log_srever')");
	}
	elsif($srcip eq '-')
	{
		$sqr_insert = $dbh->prepare("insert into log_windows_login (starttime,login_id,host,port,protocol,active,user,msg,logserver) values ('$datetime','$login_id','$host',$port,'$protocol',1,'$user','$msg','$log_srever')");
	}
	elsif($port eq '-')
	{
		$sqr_insert = $dbh->prepare("insert into log_windows_login (starttime,login_id,host,srchost,protocol,active,user,msg,logserver) values ('$datetime','$login_id','$host','$srcip','$protocol',1,'$user','$msg','$log_srever')");
	}
	else
	{
		$sqr_insert = $dbh->prepare("insert into log_windows_login (starttime,login_id,host,port,srchost,protocol,active,user,msg,logserver) values ('$datetime','$login_id','$host',$port,'$srcip','$protocol',1,'$user','$msg','$log_srever')");
	}

	$sqr_insert->execute();
	$sqr_insert->finish();
}

sub logincancel_process
{
	my($host,$msg,$datetime) = @_;
	my $user;my $login_id;

	if($msg =~ /用户名:\s*(\S+).*\s+登录\s*ID:\s+\((\S+)\)/i)
	{
		$user = $1;$login_id = $2;
	}

	my $sqr_update = $dbh->prepare("update log_windows_login set endtime='$datetime' where endtime is NULL and login_id='$login_id' and user='$user' and host='$host' and UNIX_TIMESTAMP(starttime)<=UNIX_TIMESTAMP('$datetime')");
	$sqr_update->execute();
	$sqr_update->finish();
}
