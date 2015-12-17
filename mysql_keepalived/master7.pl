#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use DBD::mysql;
use File::Basename;
use File::Copy;

our($peer_ip,$backup_ip,$interface) = @ARGV;
our $mycnf_path = "/opt/freesvr/1/etc";
$mycnf_path =~ s/\/$//;
unless(defined $peer_ip && defined $backup_ip && defined $interface)
{
    print "parameter error\n";
    exit 1;
}

our $local_ip = "";

foreach my $line(`/sbin/ifconfig $interface`)
{
	chomp $line;
	if($line =~ /^\s*inet\s+(\S+)/)
	{
		$local_ip = $1;
	}
}

if($local_ip eq "")
{
	print "ifconfig cmd err\n";
	exit 1;
}

&iptables_process($peer_ip);
&mysql_process();
&sql_process();

unless(-e "/etc/keepalived/keepalived.conf")
{
	print "/etc/keepalived/keepalived.conf 不存在\n";
	exit 1;
}

copy("/etc/keepalived/keepalived.conf","/tmp/keepalived.conf.bak");
&keepalived_process("/tmp/keepalived.conf.bak");
copy("/tmp/keepalived.conf.bak","/etc/keepalived/keepalived.conf");
unlink "/tmp/keepalived.conf.bak";

&change_rclocal();

&file_modify_process("/etc/xrdp/global.cfg","global-server",$local_ip);
&file_modify_process("/opt/freesvr/audit/sshgw-audit/etc/freesvr-ssh-proxy_config","AuditAddress",$local_ip);
&file_modify_process("/opt/freesvr/audit/etc/global.cfg","global-server",$local_ip);
&file_modify_process("/opt/freesvr/audit/ftp-audit/etc/freesvr-ftp-audit.conf","AuditAddress",$local_ip);
#&file_modify_process("/home/wuxiaolong/5_backup/backup_session.pl","our\\s+\\\$localIp",$local_ip);
&cron_modify_process("/home/wuxiaolong/5_backup/backup_session.pl");

sub iptables_process
{
    my($peer_ip) = @_;
    my $file = "/etc/sysconfig/iptables";

    my $dir = dirname $file;
    my $file_name = basename $file;
    my $backup_name = $file_name.".backup";

    unless(-e "$dir/$backup_name")
    {
        copy($file,"$dir/$backup_name");
    }

    open(my $fd_fr,"<$file");
    my @file_context;
    my $flag = 0;
    foreach my $line(<$fd_fr>)
    {
        chomp $line;
        if($line =~ /^-A\s*RH-Firewall/i)
        {
            if($flag == 0)
            {
                $flag = 1;
            }

            if($line =~ /-s\s*$peer_ip/i)
            {
                $flag = 2;
            }
        }

        if($line =~ /^-A\s*RH-Firewall.*REJECT/i && $flag == 1)
        {
            $flag = 3;
            push @file_context,"-A RH-Firewall-1-INPUT -s $peer_ip -j ACCEPT";
        }

        push @file_context,$line;
    }

    close $fd_fr;

    open(my $fd_fw,">$file");
    foreach my $line(@file_context)
    {
        print $fd_fw $line,"\n";
    }

    close $fd_fw;
    if(system("service iptables restart 1>/dev/null 2>&1") != 0)
    {
        print "iptables restart 失败\n";
        exit 1;
    }
}

sub mysql_process
{
    copy("$mycnf_path/my_master.cnf","/etc/my.cnf") or die "copy master my.cnf failed: $!";
	my $cmd = "/etc/init.d/mysqld restart 1>/dev/null 2>&1";
	if(system($cmd) != 0)
	{
		print "mysql 重启失败\n";
		exit 1;
	}
}

sub sql_process
{
	my $local_dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});
	my $utf8 = $local_dbh->prepare("set names utf8");
	$utf8->execute();
	$utf8->finish();

	my $remote_dbh=DBI->connect("DBI:mysql:database=audit_sec;host=$peer_ip;mysql_connect_timeout=5","freesvr","freesvr",{RaiseError=>1});
	$utf8 = $remote_dbh->prepare("set names utf8");
	$utf8->execute();
	$utf8->finish();

	my $sqr_exec = $remote_dbh->prepare("show master status");
	$sqr_exec->execute();
	my $ref_exec = $sqr_exec->fetchrow_hashref();
	my $remote_file = $ref_exec->{"File"};
	my $remote_position = $ref_exec->{"Position"};
	$sqr_exec->finish();

	$sqr_exec = $local_dbh->prepare("stop slave");
	$sqr_exec->execute();
	$sqr_exec->finish();

	$sqr_exec = $local_dbh->prepare("reset slave");
	$sqr_exec->execute();
	$sqr_exec->finish();

	$sqr_exec = $local_dbh->prepare("change master to master_host='$peer_ip',master_user='freesvr',master_password='freesvr',master_log_file='$remote_file',master_log_pos= $remote_position");
	$sqr_exec->execute();
	$sqr_exec->finish();

	$sqr_exec = $local_dbh->prepare("start slave");
	$sqr_exec->execute();
	$sqr_exec->finish();

	my $sqr_select = $local_dbh->prepare("select count(*) from backup_setting where ip = '$peer_ip' and dbname = 'audit_sec' and mysqluser = 'freesvr' and udf_decrypt(mysqlpasswd) = 'freesvr' and session_flag = 1");
	$sqr_select->execute();
	my $ref_select = $sqr_select->fetchrow_hashref();
	if($ref_select->{"count(*)"} == 0)
	{
		my $sqr_insert = $local_dbh->prepare("insert into backup_setting(ip,dbname,mysqluser,mysqlpasswd,session_flag) values('$peer_ip','audit_sec','freesvr',udf_encrypt('freesvr'),1)");
		$sqr_insert->execute();
		$sqr_insert->finish();
	}
	$sqr_select->finish();

    my $sqr_update = $local_dbh->prepar("replace into backup_session_device(device_ip) values ('$peer_ip')");
    $sqr_update->execute();
    $sqr_update->finish();

    $remote_dbh->disconnect();
    $local_dbh->disconnect();
}

sub keepalived_process
{
	my($file) = @_;

	my @file_context;
	my $flag = 0;

	open(my $fd_fr,"<$file");
	foreach my $line(<$fd_fr>)
	{
		chomp $line;
        if($line =~ /^\s*lvs_sync_daemon_interface/i)
        {
            next;
        }

        if($line =~ /^\s*state/i)
        {
            $line = "state MASTER";
        }

        if($line =~ /^\s*interface/)
        {
            $line = "\tinterface $interface";
        }

        if($line =~ /^\s*priority/i)
        {
            $line =~ s/\d+/100/;
        }

        if($line =~ /virtual_ipaddress/i)
        {
            $flag = 1;
        }

		if($flag == 1 && $line =~ /(\d{1,3}\.){3}\d{1,3}/)
		{
			$line =~ s/(\d{1,3}\.){3}\d{1,3}/$backup_ip/;
			$flag = 0;
		}

		push @file_context,$line;
	}
	close $fd_fr;

	open(my $fd_fw,">$file");
	foreach my $line(@file_context)
	{
		print $fd_fw $line,"\n";
	}

	close $fd_fw;
}

sub change_rclocal
{
    my $file = "/etc/rc.local";
    my $dir = dirname $file;
    my $file_name = basename $file;
    my $backup_name = $file_name.".backup";

    unless(-e "$dir/$backup_name")
    {
        copy($file,"$dir/$backup_name");
    }

    my @file_context;
    my $flag = 0;

    open(my $fd_fr,"<$file");
    foreach my $line(<$fd_fr>)
    {
        chomp $line;
        if($line =~ /\/usr\/local\/sbin\/keepalived/i)
        {
            $flag = 1;
        }

        push @file_context,$line;
    }
    close $fd_fr;
    if($flag==0)
    {
        push @file_context,"/usr/local/sbin/keepalived";
    }

    open(my $fd_fw,">$file");
    foreach my $line(@file_context)
    {
        print $fd_fw $line,"\n";
    }

    close $fd_fw;
}

sub file_modify_process
{
    my($file,$attr,$ip) = @_;
    my $dir = dirname $file;
    my $file_name = basename $file;
    my $backup_name = $file_name.".backup";

    unless(-e "$dir/$backup_name")
    {
        copy($file,"$dir/$backup_name");
    }

    open(my $fd_fr,"<$file") or die "cannot open $file";

    my @file_context;
    my $flag = 0;
    foreach my $line(<$fd_fr>)
    {
        chomp $line;
        if($line =~ /^$attr/i)
        {
            $line =~ s/(\d{1,3}\.){3}\d{1,3}/$ip/;
        }

        push @file_context,$line;
    }

    close $fd_fr;

    open(my $fd_fw,">$file");
    foreach my $line(@file_context)
    {
        print $fd_fw $line,"\n";
    }

    close $fd_fw;
}

sub cron_modify_process
{
    my($file) = @_;

    if(-e "/var/spool/cron/root")
    {
        open(my $fd_fr,"</var/spool/cron/root");
        my @file_context;
        my $flag = 0;
        foreach my $line(<$fd_fr>)
        {
            chomp $line;
            if($line =~ /$file/i)
            {
                $flag = 1;
                $line = "*/5 * * * * $file";
            }

            push @file_context,$line;
        }

        if($flag == 0)
        {
            push @file_context,"*/5 * * * * $file";
        }

        close $fd_fr;

        open(my $fd_fw,">/var/spool/cron/root");
        foreach my $line(@file_context)
        {
            print $fd_fw $line,"\n";
        }

        close $fd_fw;
    }
    else
    {
        open(my $fd_fw,">/var/spool/cron/root");
        print $fd_fw "*/5 * * * * $file\n";
        close $fd_fw;
    }
}

