#!/usr/bin/perl
use warnings;
use strict;
use Data::Dumper;
use DBI;
use DBD::mysql;
use File::Pid;
use Mail::Sender;
use Encode;
use URI::Escape;
use URI::URL;

our $pidfile = File::Pid->new({file => '/tmp/record.pid',});
if (my $num = $pidfile->running)
{   
	exit;
}
else    
{       
	$pidfile->remove;
	$pidfile = File::Pid->new({file => '/tmp/record.pid',});
	$pidfile->write;
}

our $remote_host = "10.11.0.1";
our $remote_user = "freesvr";
our $remote_passwd = "freesvr";
our $send_interval = 30;
our $log_srever = '1.1.1.1';

my($sec,$min,$hour,$mday,$mon,$year) = (localtime)[0..5];
($sec,$min,$hour,$mday,$mon,$year) = (sprintf("%02d", $sec),sprintf("%02d", $min),sprintf("%02d", $hour),sprintf("%02d", $mday),sprintf("%02d", $mon + 1),$year+1900);
our $time_now_str = "$year$mon$mday$hour$min"."00";
our $warning_time = "$year-$mon-$mday $hour:$min:00";

our $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});
our $utf8 = $dbh->prepare("set names utf8");
$utf8->execute();
$utf8->finish();

our $remote_dbh=DBI->connect("DBI:mysql:database=audit_sec;host=$remote_host;mysql_connect_timeout=5","$remote_user","$remote_passwd",{RaiseError=>1});
$utf8 = $remote_dbh->prepare("set names utf8");
$utf8->execute();
$utf8->finish();

our %filter_hash;
our %warning_hash;
our %live_hash;
our %level_hash;
our %ids_relation;
our @server_relation;
our %event;
our $is_cross_login;
our %right_login_ips;
our %sended_mail;
our %sended_sms;

our %mail_msg;
our %sms_msg;

&read_log_conf();
&init_filter_hash();
&init_warning_hash();
&init_live_hash(3);
&init_relation();
&init_event();
&init_sended_info();

my $sqr_realtime_count = $dbh->prepare("select count(*) from log_realtimelogs");
$sqr_realtime_count->execute();
my $ref_realtime_count = $sqr_realtime_count->fetchrow_hashref();
our $realtime_count = $ref_realtime_count->{"count(*)"};
$sqr_realtime_count->finish();

open(our $fd_fr,"</var/log/mem/logtest1.log") or die $!;
open(our $fd_fw, ">>./record_err.log");

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

	unless(defined $log_msg){next;}

	if($log_msg =~ /\%SYS-5-PRIV_AUTH_FAIL:\s*Authentication\s*to\s*Privilage\s*level/i || $log_msg =~ /\%SYS-5-PRIV_AUTH_PASS:\s*Privilege\s*level\s*set\s*to/i || $log_msg =~ /\%SYS-5-CONFIG_I:\s*Configured\s*from\s*console\s*by/i)
	{
		if($log_msg =~ /\((\d+\.\d+\.\d+\.\d+)\)/)
		{
			my $temp_ip = $1;
			if(defined $is_cross_login && $is_cross_login == 1 && !exists $right_login_ips{$temp_ip})
			{
				&cross_insert($log_host,$log_facility,$log_priority,$log_level,$log_tag,$log_datetime,"cisco",$log_msg);
				next;
            }
        }
    }

	&judge_relationidslog($log_host,$log_datetime,$log_msg);
	&judge_relationserverlog($log_host,$log_datetime,$log_msg);

	&judge_event($log_host,$log_facility,$log_priority,$log_level,$log_tag,$log_datetime,$log_program,$log_msg);

	my @live_judge = &live_judge($log_host,$log_facility,$log_level,$log_program,$log_msg);
	if($live_judge[0] == 1 && $realtime_count< 2000)
	{
		++$realtime_count;
		my $sqr_insertlive = $dbh->prepare("insert into log_realtimelogs(host, facility, priority, level, tag, datetime, program,msg,process,logserver) VALUES ('$log_host','$log_facility','$log_priority','$log_level','$log_tag','$log_datetime','$log_program','$log_msg',$live_judge[1],'$log_srever')");
		$sqr_insertlive->execute();
		$sqr_insertlive->finish();
	}

	my $fliter = &is_filter($log_host,$log_level,$log_facility,$log_program,$log_msg);
	my $warning = 0;
    my $mail_alarm = 0;
    my $sms_alarm = 0;
    my $instruction;

	if($fliter == 0)
	{
        my $sqr_log = $remote_dbh->prepare("insert into log_logs(host,facility,priority,level,tag,datetime,program,msg,logserver) VALUES ('$log_host','$log_facility','$log_priority','$log_level','$log_tag','$log_datetime','$log_program','$log_msg','$log_srever')");
        $sqr_log->execute();
        $sqr_log->finish();

		($warning,$mail_alarm,$sms_alarm,$instruction) = &is_waring($log_host,$log_level,$log_facility,$log_program,$log_msg);

		if($warning == 1)
		{
            my $sqr_insert = $dbh->prepare("insert into log_logs_warning(datetime,host,facility,priority,level,tag,program,msg,logserver) values('$log_datetime','$log_host','$log_facility','$log_priority','$log_level','$log_tag','$log_program','$log_msg','$log_srever')");
            $sqr_insert->execute();
            $sqr_insert->finish();

            my $sqr_select = $dbh->prepare("select max(seq) from log_logs_warning");
            $sqr_select->execute();
            my $ref_select = $sqr_select->fetchrow_hashref();
            my $last_id = $ref_select->{"max(seq)"};
            $sqr_select->finish();

            if($mail_alarm == 0)
            {
                my $sqr_update = $dbh->prepare("update log_logs_warning set mail_status=0 where seq=$last_id");
                $sqr_update->execute();
                $sqr_update->finish();
            }
            elsif(exists $sended_mail{$log_msg})
            {
                my $sqr_update = $dbh->prepare("update log_logs_warning set mail_status=3 where seq=$last_id");
                $sqr_update->execute();
                $sqr_update->finish();
            }
            else
            {
                my $sqr_select = $dbh->prepare("select email from member where uid IN(select memberid from snmp_alert_user a left join snmp_alert b on a.snmp_alert_id=b.seq where (b.groupid=(select groupid from servers where device_ip='$log_host') or b.groupid=0) and b.enable=1) and email != ''");
                $sqr_select->execute();
                while($ref_select = $sqr_select->fetchrow_hashref())
                {
                    my $email = $ref_select->{"email"};
                    if(defined $email)
                    {
                        my $warning_msg;
                        if(defined $instruction)
                        {
                            $warning_msg = "SYSLOG告警服务器:$log_host 说明:$instruction 消息:$log_msg\n";
                        }
                        else
                        {
                            $warning_msg = "SYSLOG告警服务器:$log_host $log_msg\n";
                        }

                        unless(defined $mail_msg{$email})
                        {
                            my @tmp = ($warning_msg, "($last_id");
                            $mail_msg{$email} = \@tmp;
                        }   
                        else
                        {
                            $mail_msg{$email}->[0] .= $warning_msg;
                            $mail_msg{$email}->[1] .= ",$last_id";
                        }
                    }
                }
                $sqr_select->finish();
            }

            if($sms_alarm == 0)
            {
                my $sqr_update = $dbh->prepare("update log_logs_warning set sms_status=0 where seq=$last_id");
                $sqr_update->execute();
                $sqr_update->finish();
            }
            elsif(exists $sended_sms{$log_msg})
            {
                my $sqr_update = $dbh->prepare("update log_logs_warning set sms_status=3 where seq=$last_id");
                $sqr_update->execute();
                $sqr_update->finish();
            }
            else
            {
                my $sqr_select = $dbh->prepare("select mobilenum from member where uid IN(select memberid from snmp_alert_user a left join snmp_alert b on a.snmp_alert_id=b.seq where (b.groupid=(select groupid from servers where device_ip='$log_host') or b.groupid=0) and b.enable=1) and mobilenum != ''");
                $sqr_select->execute();
                while($ref_select = $sqr_select->fetchrow_hashref())
                {
                    my $mobilenum = $ref_select->{"mobilenum"};
                    if(defined $mobilenum)
                    {
                        my $warning_msg;
                        if(defined $instruction)
                        {
                            $warning_msg = "SYSLOG告警服务器:$log_host 说明:$instruction 消息:$log_msg\n";
                        }
                        else
                        {
                            $warning_msg = "SYSLOG告警服务器:$log_host $log_msg\n";
                        }

                        unless(defined $sms_msg{$mobilenum})
                        {
                            my @tmp = ($warning_msg, "($last_id");
                            $sms_msg{$mobilenum} = \@tmp;
                        }
                        else
                        {
                            $sms_msg{$mobilenum}->[0] .= $warning_msg;
                            $sms_msg{$mobilenum}->[1] .= ",$last_id";
                        }
                    }
                }
                $sqr_select->finish();
            }
        }
    }

    my $count_level = uc($log_level);

    unless(exists $level_hash{$log_host}){$level_hash{$log_host}{$count_level} = 1;}
    else
    {
        unless(exists $level_hash{$log_host}{$count_level}){$level_hash{$log_host}{$count_level} = 1;}
        else{++$level_hash{$log_host}{$count_level};}
    }

    ++$level_hash{$log_host}{"alllog"};
    $level_hash{$log_host}{"actionlog"} = 0;
    if($live_judge[0] == 1 || $fliter == 1 || $warning == 1)
    {
        ++$level_hash{$log_host}{"actionlog"};
    }
}

foreach my $host(keys %level_hash)
{
	my @level = qw/DEBUG INFO NOTICE WARNING ERR CRIT ALERT EMERG/;
	my @level_count;
	
	foreach(@level)
	{
		unless(exists $level_hash{$host}{$_}){push @level_count,0;}
		else{push @level_count,$level_hash{$host}{$_};}
	}

	my $sqr_countinsert = $dbh->prepare("insert into log_countlogs_minuter_detailed (host,date,DEBUG,INFO,NOTICE,WARNING,ERR,CRIT,ALERT,EMERG,actionlog,alllog) values ('$host','$time_now_str',$level_count[0],$level_count[1],$level_count[2],$level_count[3],$level_count[4],$level_count[5],$level_count[6],$level_count[7],$level_hash{$host}{'actionlog'},$level_hash{$host}{'alllog'})");
	$sqr_countinsert->execute();
	$sqr_countinsert->finish();
}

close($fd_fr);
close($fd_fw);
open($fd_fw,">/var/log/mem/logtest1.log") or die $!;
close($fd_fw);  

my $mail = $dbh->prepare("select mailserver,account,password from alarm");
$mail->execute();
my $ref_mail = $mail->fetchrow_hashref();
my $mailserver = $ref_mail->{"mailserver"};
my $mailfrom = $ref_mail->{"account"};
my $mailpwd = $ref_mail->{"password"};
$mail->finish();

my $subject = "日志告警,$warning_time\n";
foreach my $email(keys %mail_msg)
{
    $mail_msg{$email}->[1] .= ")";
    my $status = &send_mail($email,$subject,$mail_msg{$email}->[0],$mailserver,$mailfrom,$mailpwd);
    if($status == 1)
    {
        print "mail success\n";
    }
    else
    {
        print "mail failure\n";
    }

    my $sqr_update = $dbh->prepare("update log_logs_warning set mail_status=$status where seq in $mail_msg{$email}->[1]");
    $sqr_update->execute();
    $sqr_update->finish();
}

foreach my $mobile(keys %sms_msg)
{
    $sms_msg{$mobile}->[1] .= ")";

    my $status = 1;
    foreach my $msg(split /\n/, $sms_msg{$mobile}->[0])
    {
        my $tmp_status = &send_msg($mobile,$msg);
        if($tmp_status == 2)
        {
            $status = 2;
        }
    }

    if($status == 1)
    {
        print "sms success\n";
    }
    else
    {
        print "sms failure\n";
    }

    my $sqr_update = $dbh->prepare("update log_logs_warning set sms_status=$status where seq in $sms_msg{$mobile}->[1]");
    $sqr_update->execute();
    $sqr_update->finish();
}

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

sub judge_relationidslog
{
	my($host,$datetime,$msg) = @_;
	if(exists $ids_relation{$host})
	{
		foreach(0..(scalar @{$ids_relation{$host}})-1)
		{
			my $content = $ids_relation{$host}->[$_][0];
			if($msg =~ /$content/i)
			{
				my $serverip;
				my $start = $ids_relation{$host}->[$_][3];
				my $end = $ids_relation{$host}->[$_][4];
				if($msg =~ /$start\s*(.*?)$end/){$serverip = $1;}

				my $sqr_insert;

				if($ids_relation{$host}->[$_][1] eq "NULL" && defined $serverip)
				{
					$sqr_insert = $dbh->prepare("insert into log_relationidslog(idsip,idsmsg,datetime,relationid,serverip) values ('$host','$msg','$datetime',$ids_relation{$host}->[$_][2],'$serverip')");
				}
				elsif($ids_relation{$host}->[$_][1] ne "NULL" && defined $serverip)
				{
					$sqr_insert = $dbh->prepare("insert into log_relationidslog(idsip,idsmsg,datetime,level,relationid,serverip) values ('$host','$msg','$datetime','$ids_relation{$host}->[$_][1]',$ids_relation{$host}->[$_][2],'$serverip')");
				}
				elsif($ids_relation{$host}->[$_][1] eq "NULL" && !(defined $serverip))
				{
					$sqr_insert = $dbh->prepare("insert into log_relationidslog(idsip,idsmsg,datetime,level,relationid) values ('$host','$msg','$datetime','$ids_relation{$host}->[$_][1]',$ids_relation{$host}->[$_][2])");
				}
				else
				{
					$sqr_insert = $dbh->prepare("insert into log_relationidslog(idsip,idsmsg,datetime,relationid) values ('$host','$msg','$datetime',$ids_relation{$host}->[$_][2])");
				}

				$sqr_insert->execute();
				$sqr_insert->finish();
			}
		}
	}
}


sub judge_relationserverlog
{
	my($host,$datetime,$msg) = @_;

	foreach(0..(scalar @server_relation)-1)
	{
		if(defined &mask_calc($host,$server_relation[$_][0]) && ($server_relation[$_][1] eq &mask_calc($host,$server_relation[$_][0])))
		{
			my $devicesmsg = $server_relation[$_][2];
			if($msg =~ /$devicesmsg/)
			{
				my $sqr_insert;
				$sqr_insert = $dbh->prepare("insert into log_relationserverlog(serverip,servermsg,datetime,relationid) values('$host','$msg','$datetime',$server_relation[$_][3])");
				$sqr_insert->execute();
				$sqr_insert->finish();
			}
		}
	}
}

sub live_judge
{
	my($host,$facility,$level,$program,$msg) = @_;
	my $temp_hash;
	$temp_hash = \%live_hash;

	my $hash_level;
	my $hash_facility;
	my $hash_msg;
	my $hash_program;

	if(exists $temp_hash->{$host}){$hash_level = $temp_hash->{$host};}
	elsif(exists $temp_hash->{"NULL"}){$hash_level = $temp_hash->{"NULL"};}
	else{return 0;}

	if(exists $hash_level->{$level}){$hash_facility = $hash_level->{$level};}
	elsif(exists $hash_level->{"NULL"}){$hash_facility = $hash_level->{"NULL"};}
	else{return 0;}

	if(exists $hash_facility->{$facility}){$hash_program = $hash_facility->{$facility};}
	elsif(exists $hash_facility->{"NULL"}){$hash_program = $hash_facility->{"NULL"};}
	else{return 0;}

	if(exists $hash_program->{$program}){$hash_msg = $hash_program->{$program};}
	elsif(exists $hash_program->{"NULL"}){$hash_msg = $hash_program->{"NULL"};}
	else{return 0;}

	foreach(keys %$hash_msg)
	{
		if($_ eq "NULL") {return(1,$hash_msg->{"NULL"});}
		if($msg =~ /$_/){return(1,$hash_msg->{$_});}
	}
	return 0;
}

sub is_filter
{
	my($host,$level,$facility,$program,$msg) = @_;
    my $ref;
    if(exists $filter_hash{$host})
    {
        $ref = $filter_hash{$host};
    }
    elsif(exists $filter_hash{"NULL"})
    {
        $ref = $filter_hash{"NULL"};
    }
    else
    {
        return 0;
    }

    if(exists $ref->{$level})
    {
        $ref = $ref->{$level};
    }
    elsif(exists $ref->{"NULL"})
    {
        $ref = $ref->{"NULL"};
    }
    else
    {
        return 0;
    }

    if(exists $ref->{$facility})
    {
        $ref = $ref->{$facility};
    }
    elsif(exists $ref->{"NULL"})
    {
        $ref = $ref->{"NULL"};
    }
    else
    {
        return 0;
    }

    if(exists $ref->{$program})
    {       
        $ref = $ref->{$program};
    }
    elsif(exists $ref->{"NULL"})
    {
        $ref = $ref->{"NULL"};
    }
    else
    {
        return 0;
    }

    if($ref->[0] eq "NULL")
    {
        return 1;
    }
    else
    {
        foreach my $regex(@$ref)
        {
            if($msg =~ /$regex/)
            {
                return 1;
            }
        }
        return 0;
    }
}

sub is_waring
{
	my($host,$level,$facility,$program,$msg) = @_;
    my $ref;
    if(exists $warning_hash{$host})
    {
        $ref = $warning_hash{$host};
    }
    elsif(exists $warning_hash{"NULL"})
    {
        $ref = $warning_hash{"NULL"};
    }
    else
    {
        return 0;
    }

    if(exists $ref->{$level})
    {
        $ref = $ref->{$level};
    }
    elsif(exists $ref->{"NULL"})
    {
        $ref = $ref->{"NULL"};
    }
    else
    {
        return 0;
    }

    if(exists $ref->{$facility})
    {
        $ref = $ref->{$facility};
    }
    elsif(exists $ref->{"NULL"})
    {
        $ref = $ref->{"NULL"};
    }
    else
    {
        return 0;
    }

    if(exists $ref->{$program})
    {       
        $ref = $ref->{$program};
    }
    elsif(exists $ref->{"NULL"})
    {
        $ref = $ref->{"NULL"};
    }
    else
    {
        return 0;
    }

    if(exists $ref->{"NULL"})
    {
        $ref = $ref->{"NULL"};
        return (1,$ref->[0],$ref->[1],$ref->[2]);
    }
    else
    {
        foreach my $regex(keys %{$ref})
        {
            if($msg =~ /$regex/)
            {
                my $arrref = $ref->{$regex};
                return (1,$arrref->[0],$arrref->[1],$arrref->[2]);
            }
        }
        return (0,0,0,undef);
    }
}

sub init_filter_hash
{
    my $sqr_select = $dbh->prepare("select host,level,facility,program,msg from log_syslog where process=1");
    $sqr_select->execute();
    while(my $ref_select = $sqr_select->fetchrow_hashref())
    {
        my $host = $ref_select->{"host"};
        if(!defined $host || $host=~/^\s*$/)
        {
            $host = "NULL";
        }

        my $level = $ref_select->{"level"};
        if(!defined $level || $level=~/^\s*$/)
        {
            $level = "NULL";
        }

        my $facility = $ref_select->{"facility"};
        if(!defined $facility || $facility=~/^\s*$/)
        {
            $facility = "NULL";
        }

        my $program = $ref_select->{"program"};
        if(!defined $program || $program=~/^\s*$/)
        {
            $program = "NULL";
        }

        my $msg = $ref_select->{"msg"};
        unless(defined $msg)
        {
            $msg = "NULL";
        }

        unless(exists $filter_hash{$host})
        {
            my %tmp;
            $filter_hash{$host} = \%tmp;
        }

        unless(exists $filter_hash{$host}->{$level})
        {
            my %tmp;
            $filter_hash{$host}->{$level} = \%tmp;
        }

        unless(exists $filter_hash{$host}->{$level}->{$facility})
        {
            my %tmp;
            $filter_hash{$host}->{$level}->{$facility} = \%tmp;
        }

        unless(exists $filter_hash{$host}->{$level}->{$facility}->{$program})
        {  
            my @tmp;
            $filter_hash{$host}->{$level}->{$facility}->{$program} = \@tmp;
        }

        if($msg eq "NULL")
        {
            $filter_hash{$host}->{$level}->{$facility}->{$program}->[0] = "NULL";
        }
        else
        {
            push @{$filter_hash{$host}->{$level}->{$facility}->{$program}}, $msg;
        }
    }
    $sqr_select->finish();
}

sub init_warning_hash
{
    my $sqr_select = $dbh->prepare("select host,level,facility,program,msg,mail_alarm,sms_alarm,instruction from log_syslog where process=2");
    $sqr_select->execute();
    while(my $ref_select = $sqr_select->fetchrow_hashref())
    {
        my $mail_alarm = $ref_select->{"mail_alarm"};
        my $sms_alarm = $ref_select->{"sms_alarm"};
        my $instruction = $ref_select->{"instruction"};

        my $host = $ref_select->{"host"};
        if(!defined $host || $host=~/^\s*$/)
        {
            $host = "NULL";
        }

        my $level = $ref_select->{"level"};
        if(!defined $level || $level=~/^\s*$/)
        {
            $level = "NULL";
        }

        my $facility = $ref_select->{"facility"};
        if(!defined $facility || $facility=~/^\s*$/)
        {
            $facility = "NULL";
        }

        my $program = $ref_select->{"program"};
        if(!defined $program || $program=~/^\s*$/)
        {
            $program = "NULL";
        }

        my $msg = $ref_select->{"msg"};
        unless(defined $msg)
        {
            $msg = "NULL";
        }

        unless(exists $warning_hash{$host})
        {
            my %tmp;
            $warning_hash{$host} = \%tmp;
        }

        unless(exists $warning_hash{$host}->{$level})
        {
            my %tmp;
            $warning_hash{$host}->{$level} = \%tmp;
        }

        unless(exists $warning_hash{$host}->{$level}->{$facility})
        {
            my %tmp;
            $warning_hash{$host}->{$level}->{$facility} = \%tmp;
        }

        unless(exists $warning_hash{$host}->{$level}->{$facility}->{$program})
        {  
            my %tmp;
            $warning_hash{$host}->{$level}->{$facility}->{$program} = \%tmp;
        }

        unless(exists $warning_hash{$host}->{$level}->{$facility}->{$program}->{$msg})
        {
            my @tmp=($mail_alarm,$sms_alarm,$instruction);
            $warning_hash{$host}->{$level}->{$facility}->{$program}->{$msg} = \@tmp;
        }
    }
    $sqr_select->finish();
}

sub init_live_hash
{
	my $sqr = $dbh->prepare("select msg,level,facility,host,program,process from log_syslog where realtime = 1");
	$sqr->execute();
	while(my $ref = $sqr->fetchrow_hashref())
	{
		my $host = defined $ref->{"host"} ? $ref->{"host"} : "NULL";
		my $level = defined $ref->{"level"} ? $ref->{"level"} : "NULL";
		my $facility = defined $ref->{"facility"} ? $ref->{"facility"} : "NULL";
		my $program = defined $ref->{"program"} ? $ref->{"program"} : "NULL";
		my $msg = defined $ref->{"msg"} ? $ref->{"msg"} : "NULL";
		my $process = defined $ref->{"process"} ? $ref->{"process"} : 0;

#		if($host eq "NULL" && $level eq "NULL" && $facility eq "NULL" && $program eq "NULL" && $msg eq "NULL") {next;}

		$live_hash{$host}{$level}{$facility}{$program}{$msg} = $process;
	}
}

sub init_relation
{
	my $sqr = $dbh->prepare("select idsip,idsmsg,idsserverip,devicesip,devicesmsg,level,seq from log_relation");
	$sqr->execute();
	while(my $ref = $sqr->fetchrow_hashref())
	{
		my $level = defined $ref->{"level"} ? $ref->{"level"} : "NULL";
		my $seq = $ref->{"seq"};
		my $idsip = $ref->{"idsip"};
		my $idsmsg = $ref->{"idsmsg"};
		my $idsserverip = $ref->{"idsserverip"};
		my $devicesip = $ref->{"devicesip"};
		my $devicesmsg = $ref->{"devicesmsg"};

		my @ids_relation_value;
		push @ids_relation_value,$idsmsg,$level,$seq;
		my ($ids_ip_strat,$ids_ip_end) = split /~~~/,$idsserverip;
		push @ids_relation_value,$ids_ip_strat,$ids_ip_end;

		push @{$ids_relation{$idsip}},\@ids_relation_value;

		my($ip,$mask) = split /\//,$devicesip;
		my $net_seg = &mask_calc($ip,$mask);

		my @server_relation_value;
		push @server_relation_value,$mask,$net_seg,$devicesmsg,$seq;

		push @server_relation,\@server_relation_value;
	}
}

sub mask_calc
{
	my($ip,$mask) = @_;
	unless(defined $ip && defined $mask){return;}
	my @ip_pos = split /\./,$ip;

	unless($ip =~ /\d+.\d+.\d+.\d+/){return;}

	if($mask <= 8)
	{
		$ip_pos[1] = $ip_pos[2] = $ip_pos[3] = 0;
		$ip_pos[0] &= (0xff<<(8-$mask));
	}
	elsif($mask > 8 && $mask <= 16)
	{
		$ip_pos[2] = $ip_pos[3] = 0;
		$ip_pos[1] &= (0xff<<(16-$mask));
	}
	elsif($mask > 16 && $mask <= 24)
	{
		$ip_pos[3] = 0;
		$ip_pos[2] &= (0xff<<(24-$mask));
	}
	else
	{
		$ip_pos[3] &= (0xff<<(32-$mask));
	}

	return join(".",@ip_pos);
}

sub init_event
{
	my $sqr = $dbh->prepare("select eventmsg,event,msg_level,logsource,pos from log_eventconfig");
	$sqr->execute();

	while(my $ref = $sqr->fetchrow_hashref())
	{
		my $eventmsg = defined $ref->{"eventmsg"} ? $ref->{"eventmsg"} : "NULL";
		if($eventmsg eq "NULL"){next;}

		my $event = defined $ref->{"event"} ? $ref->{"event"} : "NULL";
		my $msg_level = defined $ref->{"msg_level"} ? $ref->{"msg_level"} : "NULL";
		my $logsource = defined $ref->{"logsource"} ? $ref->{"logsource"} : "NULL";
		my $re_pos = defined $ref->{"pos"} ? $ref->{"pos"} : "NULL";

		unless(exists $event{$eventmsg})
		{
			my @value;
			push @value,$event,$msg_level,$logsource,$re_pos;
			$event{$eventmsg} = \@value;
		}
	}

	$sqr->finish();
}

sub judge_event
{
    my($host,$facility,$priority,$level,$tag,$datetime,$program,$msg) = @_;
    foreach my $key(keys %event)
    {
        if($msg =~ /$key/i)
        {
            my $msg_level = $event{$key}->[1];
            my $event = $event{$key}->[0];
			my $logsource = $event{$key}->[2];
			my $re_pos = $event{$key}->[3];
			my $pos;

			my $sqr_insert;

			if($msg_level eq "NULL" || $event eq "NULL" || $logsource eq "NULL"){return;}
			
			if($re_pos ne "NULL" && $msg =~ /$re_pos/i)
			{
				$pos = $1;

				$sqr_insert = $dbh->prepare("insert into log_eventlogs (host, facility, priority, level, tag, datetime, program,msg,logserver,msg_level,event,logsource,pos) values ('$host','$facility','$priority','$level','$tag','$datetime','$program','$msg','$log_srever',$msg_level,'$event','$logsource','$pos')");
			}
			else
			{
				$sqr_insert = $dbh->prepare("insert into log_eventlogs (host, facility, priority, level, tag, datetime, program,msg,logserver,msg_level,event,logsource) values ('$host','$facility','$priority','$level','$tag','$datetime','$program','$msg','$log_srever',$msg_level,'$event','$logsource')");
			}

            $sqr_insert->execute();
            $sqr_insert->finish();
            return;
        }
    }
}

sub init_sended_info
{
    my $sqr_select = $dbh->prepare("select msg from log_logs_warning where datetime>=('$time_now_str'-interval $send_interval minute) and mail_status=1");
    $sqr_select->execute();
    while(my $ref_select = $sqr_select->fetchrow_hashref())
    {
        my $msg = $ref_select->{"msg"};
        unless(exists $sended_mail{$msg})
        {
            $sended_mail{$msg} = 1;
        }
    }
    $sqr_select->finish();

    $sqr_select = $dbh->prepare("select msg from log_logs_warning where datetime>=('$time_now_str'-interval $send_interval minute) and sms_status=1");
    $sqr_select->execute();
    while(my $ref_select = $sqr_select->fetchrow_hashref())
    {
        my $msg = $ref_select->{"msg"};
        unless(exists $sended_sms{$msg})
        {
            $sended_sms{$msg} = 1;
        }
    }
    $sqr_select->finish();
}

sub send_mail 
{   
    my($mailto,$subject,$msg,$mailserver,$mailfrom,$mailpwd) = @_;

    print "$mailto\n$msg\n";
    my $sender = new Mail::Sender;
#   $subject = encode_mimewords($subject,'Charset','UTF-8');
    $subject =  encode("gb2312", decode("utf8", $subject));           #freesvr 专用;
#   $msg = encode_mimewords($msg,'Charset','gb2312');
    $msg =  encode("gb2312", decode("utf8", $msg));              #freesvr 专用;

    if ($sender->MailMsg({
                smtp => $mailserver,
                from => $mailfrom,
                to => $mailto,
                subject => $subject,
                msg => $msg,
                auth => 'LOGIN',
                authid => $mailfrom,
                authpwd => $mailpwd,
#               encoding => 'gb2312',
                })<0){
        return 2;
    }
    else
    {
        return 1;
    }
}

sub send_msg
{   
    my ($mobile_tel,$msg) = @_;
    print "$mobile_tel\n$msg\n";
    my $sp_no = "955589903";
    my $mobile_type = "1";
    $msg =  encode("gb2312", decode("utf8", $msg));
    $msg = uri_escape($msg);

    my $url = "http://192.168.4.71:8080/smsServer/service.action?branch_no=10&password=010&depart_no=10001&message_type=1&batch_no=4324&priority=1&sp_no=$sp_no&mobile_type=$mobile_type&mobile_tel=$mobile_tel&message=$msg";

    print "$url\n";

    $url = URI::URL->new($url);

    if(system("wget -t 1 -T 3 '$url' -O - 1>/dev/null 2>&1") == 0)
    {   
        return 1;
    }
    else
    {   
        return 2;
    }
}
