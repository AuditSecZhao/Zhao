#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use DBD::mysql;
use Expect;
use File::HomeDir;
use Crypt::CBC;
use MIME::Base64;

our @exec_info;
our $max_process_num = 5;
our $exist_process = 0;

our $time_now_utc = time;
my($min,$hour,$mday,$mon,$year) = (localtime $time_now_utc)[1..5];
($min,$hour,$mday,$mon,$year) = (sprintf("%02d", $min),sprintf("%02d", $hour),sprintf("%02d", $mday),sprintf("%02d", $mon + 1),$year+1900);
our $time_now_str = "$year$mon$mday$hour$min"."00";

our($mysql_user,$mysql_passwd) = &get_local_mysql_config();
my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5",$mysql_user,$mysql_passwd,{RaiseError=>1});

my $utf8 = $dbh->prepare("set names utf8");
$utf8->execute();
$utf8->finish();

my $sqr_select = $dbh->prepare("select id,deviceid,scriptpath from autorun_index");
$sqr_select->execute();
while(my $ref_select = $sqr_select->fetchrow_hashref())
{
    my $id = $ref_select->{"id"};
    my $device_id = $ref_select->{"deviceid"};
    my $script_path = $ref_select->{"scriptpath"};
    my @tmp = ($id,$device_id,$script_path);
    push @exec_info, \@tmp;
}
$sqr_select->finish();
$dbh->disconnect();

if(scalar @exec_info == 0) 
{
    exit;
}

if($max_process_num > scalar @exec_info)
{
    $max_process_num = scalar @exec_info;
}

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
    my $temp = shift @exec_info;
    unless(defined $temp){return;}
    my $pid = fork();
    if (!defined($pid))
    {
        print "Error in fork: $!";
        exit 1;
    }

    if ($pid == 0)
    {
        my $id = $temp->[0];
        my $device_id = $temp->[1];
        my $script_path = $temp->[2];

        my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5",$mysql_user,$mysql_passwd,{RaiseError=>1});

        my $utf8 = $dbh->prepare("set names utf8");
        $utf8->execute();
        $utf8->finish();

        my $sqr_select = $dbh->prepare("select device_ip,username,udf_decrypt(cur_password) from devices where id=$device_id");
        $sqr_select->execute();
        my $ref_select = $sqr_select->fetchrow_hashref();
        my $device_ip = $ref_select->{"device_ip"};
        my $username = $ref_select->{"username"};
        my $passwd = $ref_select->{"udf_decrypt(cur_password)"};
        $sqr_select->finish();

        if(defined $device_ip && defined $username && defined $passwd)
        {
            &auto_run($dbh,$id,$device_ip,$username,$passwd,$script_path);
        }
        else
        {
            print "cant find deviceid($device_id) info in devices\n";
        }

        $dbh->disconnect();
        exit 0;
    }
    ++$exist_process;
}

sub auto_run
{
    my($dbh,$id,$device_ip,$username,$passwd,$script_path) = @_;

    my $cmd = "ssh -l $username $device_ip -p 2288";

    my $count = 0;
    my $flag = 1;

    while($count < 10 && $flag == 1)
    {
        ++$count;
        my $rsa_flag = 0;

        my $exp = Expect->new;
        $exp->log_stdout(0);
        $exp->spawn($cmd);
        $exp->debug(0);

        my @results = $exp->expect(20,
                [
                qr/~\]\s*[#\$]/i,
                sub {
                $flag = 0;
                }
                ],

                [
                qr/continue connecting.*yes\/no.*/i,
                sub {
                my $self = shift ;
                $self->send_slow(0.1,"yes\n");
                exp_continue;
                }
                ],

                [
                qr/password:/i,
                sub {
                my $self = shift ;
                $self->send_slow(0.1,"$passwd\n");
                exp_continue;
                }
                ],

                    [
                        qr/Host key verification failed/i,
                    sub
                    {
                        my $tmp = &rsa_err_process($dbh,$username,$device_ip);
                        if($tmp == 0)
                        {
                            $rsa_flag = 1;
                        }
                        else
                        {
                            $rsa_flag = 2;
                        }
                    }
                ],

                    [
                        qr/Permission denied/i,
                    sub
                    {
                        &err_process($dbh,$device_ip,"ssh passwd error");
                        $flag = 3;
                    }
                ],
                    );

                if($rsa_flag == 1)
                {
                    $flag = 1;
                }
                elsif($rsa_flag == 2)
                {
                    $flag = 2;
                }
                elsif($rsa_flag == 0 && $flag != 0 && $flag != 3)
                {
                    $flag = 4;
                }

                if($flag == 0)
                {
                    my $output;
                    $exp->send("$script_path\n");

                    while(1)
                    {
                        my $exec_flag = 0;
                        $exp->expect(2, undef);
                        foreach my $line(split /\n/,$exp->before())
                        {
                            $line =~ s/\r//g;
                            $line =~ s/^\s*//g;
                            $output .= "$line\n";

                            if($line =~ /~\]/)
                            {
                                $exec_flag = 1;
                                last;
                            }
                        }

                        if($exec_flag == 1)
                        {
                            last;
                        }

                        $exp->clear_accum();
                    }

                    open(my $fd_fw,">/opt/freesvr/audit/autorun/record/id_$id-$time_now_str");
                    print $fd_fw $output;
                    close $fd_fw;

                    my $sqr_insert = $dbh->prepare("insert into autorun_log(serverip,checktime,statuts,recordpath) values('$device_ip','$time_now_str',1,'/opt/freesvr/audit/autorun/record/id_$id-$time_now_str')");
                    $sqr_insert->execute();
                    $sqr_insert->finish();
                }
                elsif($flag == 4)
                {
                    if(defined $results[1])
                    {
                        &err_process($dbh,$device_ip,"$cmd exec error");
                    }
                }

                $exp->close();
    }

    if($count >= 10)
    {
        &err_process($dbh,$device_ip,"rsa err and fail to fix");
        return;
    }
}

sub rsa_err_process
{
    my($dbh,$user,$ip) = @_;
    my $home = File::HomeDir->users_home($user);
    unless(defined $home)
    {
        &err_process($dbh,$ip,"cant find home dir for user $user");
        return 1;
    }   

    my @file_lines;
    $home =~ s/\/$//;
    open(my $fd_fr,"<$home/.ssh/known_hosts");
    foreach my $line(<$fd_fr>)
    {   
        if($line =~ /^$ip/)
        {   
            next;
        }

        push @file_lines,$line;
    }
    close $fd_fr;

    open(my $fd_fw,">$home/.ssh/known_hosts");
    foreach my $line(@file_lines)
    {
        print $fd_fw $line;
    }
    close $fd_fw;

    return 0;
}

sub err_process
{
    my($dbh,$device_ip,$err_str) = @_;
    print $err_str,"\n";
    my $sqr_insert = $dbh->prepare("insert into autorun_log(serverip,checktime,statuts,message) values('$device_ip','$time_now_str',0,'$err_str')");
    $sqr_insert->execute();
    $sqr_insert->finish();
}

sub get_local_mysql_config
{
    my $tmp_mysql_user = "root";
    my $tmp_mysql_passwd = "";
    open(my $fd_fr, "</opt/freesvr/audit/etc/perl.cnf");
    while(my $line = <$fd_fr>)
    {
        $line =~ s/\s//g;
        my($name, $val) = split /:/, $line;
        if($name eq "mysql_user")
        {
            $tmp_mysql_user = $val;
        }
        elsif($name eq "mysql_passwd")
        {
            $tmp_mysql_passwd = $val;
        }
    }

    my $cipher = Crypt::CBC->new( -key => 'freesvr', -cipher => 'Blowfish', -iv => 'freesvr1', -header => 'none');
    $tmp_mysql_passwd = decode_base64($tmp_mysql_passwd);
    $tmp_mysql_passwd  = $cipher->decrypt($tmp_mysql_passwd);
    close $fd_fr;
    return ($tmp_mysql_user, $tmp_mysql_passwd);
}
