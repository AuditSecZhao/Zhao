#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use DBD::mysql;
use Expect;
use File::HomeDir;

our $time_now_utc = time;
my($min,$hour,$mday,$mon,$year) = (localtime $time_now_utc)[1..5];
($min,$hour,$mday,$mon,$year) = (sprintf("%02d", $min),sprintf("%02d", $hour),sprintf("%02d", $mday),sprintf("%02d", $mon + 1),$year+1900);
our $time_now_str = "$year$mon$mday$hour$min"."00";
our $date_today = "$year-$mon-$mday";

our $local_ip;
foreach my $line(`/sbin/ifconfig eth0`)
{
    chomp $line;
    if($line =~ /inet addr\s*:\s*(\S+)/)
    {
        $local_ip = $1;
    }
}

our $backup_file = "password-$local_ip-$date_today.zip";

my $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});
my $utf8 = $dbh->prepare("set names utf8");
$utf8->execute();
$utf8->finish();

if(-e "/tmp/$backup_file")
{
    unlink "/tmp/$backup_file";
}

if(-e "/opt/freesvr/audit/etc/changepassword/key.sql")
{
    unlink "/opt/freesvr/audit/etc/changepassword/key.sql";
}

if(system("mysqldump --opt audit_sec passwordkey > /opt/freesvr/audit/etc/changepassword/key.sql") != 0)
{
    &log_process(undef,"mysqldump err");
    exit 1;
}

chdir "/opt/freesvr/audit/etc/changepassword/";

#if(system("tar -zcpf /tmp/$backup_file *") != 0)
if(system("zip -r /tmp/$backup_file *") != 0)
{
    &log_process(undef,"zip meet err");
    exit 1;
}

my $sqr_select = $dbh->prepare("select ip,port,path,user,udf_decrypt(passwd),protocol from backup_setting where session_flag=100");
$sqr_select->execute();
while(my $ref = $sqr_select->fetchrow_hashref())
{
    my $ip = $ref->{"ip"};
    my $port = $ref->{"port"};
    my $path = $ref->{"path"};
    my $user = $ref->{"user"};
    my $passwd = $ref->{"udf_decrypt(passwd)"};
    my $protocol = $ref->{"protocol"};

    if($protocol =~ /sftp/i)
    {
        my $cmd = "sftp -oPort=$port $user\@$ip";
        &sftp_process($ip,$passwd,$user,$path,$cmd);
    }
    else
    {
        my $cmd = "ftp $ip";
        &ftp_process($ip,$passwd,$user,$path,$cmd);   
    }
}
$sqr_select->finish();

if(-e "/tmp/$backup_file")
{
    unlink "/tmp/$backup_file";
}

if(-e "/opt/freesvr/audit/etc/changepassword/key.sql")
{
    unlink "/opt/freesvr/audit/etc/changepassword/key.sql";
}

sub sftp_process
{
    my($ip,$passwd,$user,$path,$cmd) = @_;

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

        my @results = $exp->expect(300,
                [
                qr/password:/i,
                sub {
                my $self = shift ;
                $self->send_slow(0.1,"$passwd\n");
                exp_continue;
                }
                ],

                [
                qr/sftp>/i,
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
                        qr/Host key verification failed/i,
                    sub
                    {
                        my $tmp = &rsa_err_process($user,$ip);
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
                        &log_process($ip,"passwd err");
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
                    my $success_flag = 0;
                    $cmd = "put /tmp/$backup_file $path";
#                    $cmd = "put /home/lwm_2014_3_19.tar.gz $path";
                    $exp->send("$cmd\n");
                    $exp->expect(2, undef);

                    foreach my $line(split /\n/,$exp->before())
                    {
                        my $percentage;

                        if($line =~ /(\d+)%/)
                        {
                            $percentage = $1;
                            $success_flag = 1;
                        }

                        if(defined $percentage && $percentage == 100)
                        {
                            $success_flag = 2;
                            last;
                        }
                    }

                    if($success_flag == 0)
                    {
                        &log_process($ip,"$cmd exec err in sftp");
                    }
                    else
                    {
                        if($success_flag == 2)
                        {
                            &log_process($ip,"success finish");
                        }
                        else
                        {
                            while(1)
                            {
                                $exp->expect(1, undef);
                                foreach my $line(split /\n/,$exp->before())
                                {
                                    if($line =~ /100%/)
                                    {
                                        &log_process($ip,"success finish");
                                        $success_flag = 2;
                                        last;
                                    }
                                }

                                if($success_flag == 2)
                                {
                                    last;
                                }
                            }
                        }
                    }
                }
                elsif($flag == 4)
                {
                    if(defined $results[1])
                    {
                        &log_process($ip,"$cmd exec error");
                    }
                }

                $exp->close();
    }

    if($count >= 10)
    {
        &log_process($ip,"rsa err and fail to fix");
        return;
    }
}

sub rsa_err_process
{
    my($user,$ip) = @_;
    my $home = File::HomeDir->users_home($user);
    unless(defined $home)
    {
        &log_process($ip,"cant find home dir for user $user");
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

sub ftp_process
{
     my($ip,$passwd,$user,$path,$cmd) = @_; 
     $path =~ s/\/$//;

     my $exp = Expect->new;
     $exp->log_stdout(0);
     $exp->spawn($cmd);
     $exp->debug(0);

     my $flag = 1;

     my @results = $exp->expect(300,
             [
             qr/Name.*:/i,
             sub {
             my $self = shift ;
             $self->send_slow(0.1,"$user\n");
             exp_continue;
             }
             ],

             [
             qr/Password:/i,
             sub {
             my $self = shift ;
             $self->send_slow(0.1,"$passwd\n");
             exp_continue;
             }
             ],

             [
             qr/ftp>/i,
             sub {
                 $flag = 0;
             }
             ],
                 );

             if($flag == 0)
             {
                 $flag = 1;
                 $cmd = "binary";
                 $exp->send("$cmd\n");
                 $exp->expect(2, undef);
                 foreach my $line(split /\n/,$exp->before())
                 {
                     if($line =~ /200.*set to I/i)
                     {
                         $flag = 0;
                         last;
                     }
                 }

                 if($flag != 0)
                 {
                     &log_process($ip,"ftp set binary mode fail");
                 }
                 else
                 {
                     $flag = 1;
#                    $cmd = "put /home/lwm_2014_3_19.tar.gz $path/lwm_2014_3_19.tar.gz";
                     $cmd = "put /tmp/passwd.zip $path/passwd.zip";
                     $exp->send("$cmd\n");
                     $exp->expect(2, undef);

                     foreach my $line(split /\n/,$exp->before())
                     {
                         if($flag == 0)
                         {
                             $flag = 2;
                             if($line =~ /Transfer complete/i)
                             {
                                 &log_process($ip,"ftp success");
                             }
                             else
                             {
                                 &log_process($ip,"ftp fail");
                             }
                             last;
                         }

                         if($line =~ /Opening BINARY mode data connection/i)
                         {
                             $flag = 0;
                         }
                     }
                     $exp->clear_accum();

                     if($flag == 0)
                     {
                         while(1)
                         {
                             $exp->expect(1, undef);
                             foreach my $line(split /\n/,$exp->before())
                             {
                                 $flag = 2;
                                 if($line =~ /Transfer complete/i)
                                 {
                                     &log_process($ip,"ftp success");
                                 }
                                 else
                                 {
                                     &log_process($ip,"ftp fail");
                                 }
                                 last;
                             }

                             if($flag == 2)
                             {
                                 last;
                             }
                         }
                     }
                 }
             }
             else
             {
                 if(defined $results[1])
                 {
                     &log_process($ip,"$cmd exec error");
                 }
             }
}

sub log_process
{
    my($host,$err_str) = @_;

    my $cmd;

    if(defined $host)
    {
        $cmd = "insert into backup_passwd_log(datetime,host,reason) values('$time_now_str','$host','$err_str')";
    }
    else
    {
        $cmd = "insert into backup_passwd_log(datetime,reason) values('$time_now_str','$err_str')";
    }

    my $insert = $dbh->prepare("$cmd");
    $insert->execute();
    $insert->finish();
}
