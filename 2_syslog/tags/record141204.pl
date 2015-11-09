#!/usr/bin/perl
use warnings;
use strict;
use Data::Dumper;
use DBI;
use DBD::mysql;
use File::Pid;

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

our $log_srever = '1.1.1.1';
our $dbh;
our %filter_hash;
our %warning_hash;
our %live_hash;
our $last_sendtime = 0;
our $last_sendhost="";
our $last_sendmsg="";
our %level_hash;
our %ids_relation;
our @server_relation;
our %event;
our $is_cross_login;
our %right_login_ips;

$SIG{CHLD} = 'IGNORE';

&read_log_conf();
&init_mysql();
&init_filter_warn_hash(1);
&init_filter_warn_hash(2);
&init_live_hash(3);
&init_relation();
&init_event();

my($sec,$min,$hour,$mday,$mon,$year) = (localtime)[0..5];
($sec,$min,$hour,$mday,$mon,$year) = (sprintf("%02d", $sec),sprintf("%02d", $min),sprintf("%02d", $hour),sprintf("%02d", $mday),sprintf("%02d", $mon + 1),$year+1900);

our $sys_time = "$year$mon$mday$hour$min"."00";

=pod
my $sqr_mail = $dbh->prepare("select smtpip,smtpuser,smtppwd from cacti.alert_mailsms");
$sqr_mail->execute();
my $ref_mail = $sqr_mail->fetchrow_hashref();
our $mailserver = $ref_mail->{"smtpip"};
our $mailfrom = $ref_mail->{"smtpuser"};
our $mailpwd = $ref_mail->{"smtppwd"};
$sqr_mail->finish();
=cut

my $sqr_realtime_count = $dbh->prepare("select count(*) from log_realtimelogs");
$sqr_realtime_count->execute();
my $ref_realtime_count = $sqr_realtime_count->fetchrow_hashref();
our $realtime_count = $ref_realtime_count->{"count(*)"};
$sqr_realtime_count->finish();

open(our $fd_fr,"</var/log/mem/logtest1.log") or die $!;

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

	my $fliter = &filter_warn_judge(1,$log_host,$log_facility,$log_level,$log_program,$log_msg);
	my $warning = 0;

	if($fliter == 0)
	{
		$warning = &filter_warn_judge(2,$log_host,$log_facility,$log_level,$log_program,$log_msg);
=pod
		if($warning == 1)
		{
			my $now_time = time;
			if(($now_time-$last_sendtime > $alert_interval) && ($last_sendhost ne $log_host) && ($last_sendmsg ne $log_msg))
			{
				$last_sendtime = $now_time;
				$last_sendhost = $log_host;
				$$last_sendmsg = $log_msg;

				defined(my $pid = fork) or die "cannot fork:$!";
				unless($pid){
					&send_mail($log);
					exit;
				}
				else
=cut
				{
					my $sqr_log = $dbh->prepare("insert into log_logs(host, facility, priority, level, tag, datetime, program,msg,logserver) VALUES ('$log_host','$log_facility','$log_priority','$log_level','$log_tag','$log_datetime','$log_program','$log_msg','$log_srever')");
					$sqr_log->execute();
					$sqr_log->finish();
				}

#			}
#		}

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
	if($live_judge[0] == 1 || $fliter == 1 || $warning == 1){++$level_hash{$log_host}{"actionlog"};}


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

	my $sqr_countinsert = $dbh->prepare("insert into log_countlogs_minuter_detailed (host,date,DEBUG,INFO,NOTICE,WARNING,ERR,CRIT,ALERT,EMERG,actionlog,alllog) values ('$host','$sys_time',$level_count[0],$level_count[1],$level_count[2],$level_count[3],$level_count[4],$level_count[5],$level_count[6],$level_count[7],$level_hash{$host}{'actionlog'},$level_hash{$host}{'alllog'})");
	$sqr_countinsert->execute();
	$sqr_countinsert->finish();
}

close($fd_fr);
open(our $fd_fw,">/var/log/mem/logtest1.log") or die $!;
close($fd_fw);  
$pidfile->remove;

=pod
foreach my $host(keys %live_hash)
{
	my %hash_level = %{$live_hash{$host}};
	foreach my $level(keys %hash_level)
	{
		my %hash_facility= %{$hash_level{$level}};
		foreach my $facility(keys %hash_facility)
		{
			my %msg_arr = %{$hash_facility{$facility}};
			print $host,"\t",$level,"\t",$facility,"\t";
			foreach my $msg(keys %msg_arr)
			{
#				print $msg,",",$msg_arr{$msg};
				if($msg eq "NULL")
				{
					print ",NULL";
					last;
				}
				else
				{
					print ",",$msg;
				}
			}
			print "\n";
		}
	}
}
=cut

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

sub filter_warn_judge
{
	my($class,$host,$facility,$level,$program,$msg) = @_;
	my $temp_hash;
	if($class == 1){$temp_hash = \%filter_hash;}
	if($class == 2){$temp_hash = \%warning_hash;}

	my $hash_level;
	my $hash_facility;
	my $msg_arr;
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

	if(exists $hash_program->{$program}){$msg_arr = $hash_program->{$program};}
	elsif(exists $hash_program->{"NULL"}){$msg_arr = $hash_program->{"NULL"};}
	else{return 0;}

	if($msg_arr->[0] eq "NULL"){return 1;}
	else
	{
		foreach (@$msg_arr)
		{
			if($msg =~ /$_/){return 1;}
		}
		return 0;
	}
}

sub init_mysql
{
	our $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});
	our $utf8 = $dbh->prepare("set names utf8");
	$utf8->execute();
	$utf8->finish();
}

sub init_filter_warn_hash
{
	my ($class) = @_;
	my $sqr;my $temp_hash;
	if($class == 1)
	{
		$sqr = $dbh->prepare("select msg,level,facility,host,program from log_syslog where process = 1");
		$temp_hash = \%filter_hash;
	}
	if($class == 2)
	{
		$sqr = $dbh->prepare("select msg,level,facility,host,program from log_syslog where process = 2");
		$temp_hash = \%warning_hash;
	}

	$sqr->execute();
	while(my $ref = $sqr->fetchrow_hashref())
	{
		my $host = defined $ref->{"host"} ? $ref->{"host"} : "NULL";
		my $level = defined $ref->{"level"} ? $ref->{"level"} : "NULL";
		my $facility = defined $ref->{"facility"} ? $ref->{"facility"} : "NULL";
		my $program = defined $ref->{"program"} ? $ref->{"program"} : "NULL";
		my $msg = defined $ref->{"msg"} ? $ref->{"msg"} : "NULL";

#		if($host eq "NULL" && $level eq "NULL" && $facility eq "NULL" && $program eq "NULL" && $msg eq "NULL") {next;}
		if($msg eq "NULL")
		{
			$temp_hash->{$host}{$level}{$facility}{$program}[0] = "NULL";
		}
		else
		{
			push @{$temp_hash->{$host}{$level}{$facility}{$program}}, $msg;
		}
	}
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


=pod
sub send_mail
{
	my $log = $_;
	my $msg = $alert_mail_content;
	$msg =~ s/\$MSG\$/$log/;
	my $subject = $alert_mail_title;

	$subject = encode("gb2312", decode("utf8", $subject));
	$msg =  encode("gb2312", decode("utf8", $msg));

	my $sender = new Mail::Sender;
	if ($sender->MailMsg({
				smtp => $mailserver,
				from => $mailfrom,
				to => $mailto,
				subject => $subject,
				msg => $msg,
				auth => 'LOGIN',
				authid => $mailfrom,
				authpwd => $mailpwd,
				})<0){
		return 2;
	}
	else
	{
		return 1;
	}

}
=cut
