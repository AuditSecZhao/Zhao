#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use DBD::mysql;
use Getopt::Long;
use File::Copy;
use File::Basename;
use Crypt::CBC;
use MIME::Base64;

#ssh-keygen -t rsa -N "" -f /home/wuxiaolong/aa

our($mysql_user,$mysql_passwd) = &get_local_mysql_config();
our $is_force = 0;
our $group_name = undef;
our $server_name = undef;
our $user_name = undef;

our $time_now_utc = time;
my($min,$hour,$mday,$mon,$year) = (localtime $time_now_utc)[1..5];
($min,$hour,$mday,$mon,$year) = (sprintf("%02d", $min),sprintf("%02d", $hour),sprintf("%02d", $mday),sprintf("%02d", $mon + 1),$year+1900);
our $time_now_str = "$year$mon$mday$hour$min"."00";

our %ssh_key_info;
our %not_modify_key;

GetOptions("g=s"=>\$group_name,"s=s"=>\$server_name,"u=s"=>\$user_name,"f"=>\$is_force);

our $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=5",$mysql_user,$mysql_passwd,{RaiseError=>1});
our $utf8 = $dbh->prepare("set names utf8");
$utf8->execute();
$utf8->finish();

our $load_modify_sql = "
select 
d.id,d.device_ip,d.username,d.port,d.automodify,unix_timestamp(d.last_update_time) last_update_time,s.month,s.week,s.user_define,b.sshkeyname,b.sshprivatekey,b.sshpublickey,udf_decrypt(b.keypassword) keypassword 
from sshkey a 
left join sshkeyname b on a.sshkeyname=b.id 
left join devices d on a.devicesid=d.id
left join servers s on s.device_ip=d.device_ip
where b.id is not null order by sshprivatekey";

my $sqr_select = $dbh->prepare($load_modify_sql);
$sqr_select->execute();
while(my $ref_select = $sqr_select->fetchrow_hashref())
{
    my $device_id = $ref_select->{"id"};
    my $device_ip = $ref_select->{"device_ip"};
    my $username = $ref_select->{"username"};
    my $port = $ref_select->{"port"};
    my $automodify = $ref_select->{"automodify"};
    my $last_update_time = $ref_select->{"last_update_time"};
    my $month = $ref_select->{"month"};
    my $week = $ref_select->{"week"};
    my $user_define = $ref_select->{"user_define"};
    my $sshkeyname = $ref_select->{"sshkeyname"};
    my $sshprivatekey = $ref_select->{"sshprivatekey"};
    my $sshpublickey = $ref_select->{"sshpublickey"};
    my $keypassword = $ref_select->{"keypassword"};

    if($automodify == 0)
    {
        if(exists $ssh_key_info{$sshkeyname})
        {
            delete $ssh_key_info{$sshkeyname};
        }

        unless(exists $not_modify_key{$sshkeyname})
        {
            $not_modify_key{$sshkeyname} = 1;
        }
        next;
    }

    if($is_force)
    {
        unless(exists $ssh_key_info{$sshkeyname})
        {
            my @tmp;
            my @key_info = ($sshprivatekey,$sshpublickey,\@tmp);
            $ssh_key_info{$sshkeyname} = \@key_info;
        }
        my @user_info = ($device_id,$device_ip,$username,$port);
        push @{$ssh_key_info{$sshkeyname}->[2]}, \@user_info;
    }
    elsif(&check_modify($last_update_time,$month,$week,$user_define) && !exists $not_modify_key{$sshkeyname})
    {
        unless(exists $ssh_key_info{$sshkeyname})
        {
            my @tmp;
            my @key_info = ($sshprivatekey,$sshpublickey,\@tmp);
            $ssh_key_info{$sshkeyname} = \@key_info;
        }
        my @user_info = ($device_id,$device_ip,$username,$port);
        push @{$ssh_key_info{$sshkeyname}->[2]}, \@user_info;
    }
    else
    {
        if(exists $ssh_key_info{$sshkeyname})
        {
            delete $ssh_key_info{$sshkeyname};
        }

        unless(exists $not_modify_key{$sshkeyname})
        {
            $not_modify_key{$sshkeyname} = 1;
        }
    }
}
$sqr_select->finish();

&init_env();

foreach my $sshkeyname(keys %ssh_key_info)
{
    my $sshprivatekey = $ssh_key_info{$sshkeyname}->[0];
    my $sshpublickey = $ssh_key_info{$sshkeyname}->[1];
    print $sshpublickey,"\n";

    &log_process("copy old key pair to /opt/freesvr/audit/sshgw-audit/keys/pvt_old/ & /opt/freesvr/audit/sshgw-audit/keys/pub_old/");
    copy($sshprivatekey, ("/opt/freesvr/audit/sshgw-audit/keys/pvt_old/". basename $sshprivatekey));
    copy($sshpublickey, ("/opt/freesvr/audit/sshgw-audit/keys/pub_old/". basename $sshpublickey));
    &log_process("finish copy old key pair to /opt/freesvr/audit/sshgw-audit/keys/pvt_old/ & /opt/freesvr/audit/sshgw-audit/keys/pub_old/");

    if(&generate_keys(basename $sshprivatekey))
    {
        next;
    }

    &log_process("copy new key pair to /opt/freesvr/audit/sshgw-audit/keys/pvt_new/ & /opt/freesvr/audit/sshgw-audit/keys/pub_new/");
    copy(("/tmp/". basename $sshprivatekey), ("/opt/freesvr/audit/sshgw-audit/keys/pvt_new/". basename $sshprivatekey));
    copy(("/tmp/". basename $sshprivatekey. ".pub"), ("/opt/freesvr/audit/sshgw-audit/keys/pub_new/". basename $sshpublickey));
    if((chmod 0400, ("/opt/freesvr/audit/sshgw-audit/keys/pvt_new/". basename $sshprivatekey),("/opt/freesvr/audit/sshgw-audit/keys/pub_new/". basename $sshpublickey)) != 2)
    {
        &log_process("change mode for new key pair error in /opt/freesvr/audit/sshgw-audit/keys/pub_new/". basename $sshpublickey);
        next;
    }
    &log_process("finish copy old key pair to /opt/freesvr/audit/sshgw-audit/keys/pvt_new/ & /opt/freesvr/audit/sshgw-audit/keys/pub_new/");
    unlink "/tmp/". basename $sshprivatekey;
    unlink "/tmp/". basename $sshprivatekey. ".pub";

    my $pubkey = &get_pub_key("/opt/freesvr/audit/sshgw-audit/keys/pub_new/". basename $sshpublickey);
    foreach my $ref(@{$ssh_key_info{$sshkeyname}->[2]})
    {
        my $device_id = $ref->[0];
        my $device_ip = $ref->[1];
        my $user = $ref->[2];
        my $port = $ref->[3];

        if(system("/home/wuxiaolong/ssh_authorize/ssh_test.pl -h $device_ip -p $port -i $sshprivatekey -u $user")!=0)
        {
            &log_process("cannot ssh to $device_ip by $user with pvt key $sshprivatekey\n");
            next;
        }

        &log_process("modify authorized_key for $device_ip");
        unless(-e "/opt/freesvr/audit/sshgw-audit/keys/authorized_keys/${device_ip}_${user}")
        {
            &log_process("authorized_keys for ${device_ip}_${user} not exists");
            next;
        }

        &modify_authorized_key($device_id,$pubkey,"/opt/freesvr/audit/sshgw-audit/keys/authorized_keys/${device_ip}_${user}");
        &log_process("finish modify authorized_key for $device_ip");
        &log_process("scp authorized_key to $user\@$device_ip");
        &scp_to_remote($device_ip,$user,$port,$sshprivatekey,"/opt/freesvr/audit/sshgw-audit/keys/authorized_keys/${device_ip}_${user}");
        &log_process("finish scp authorized_key to $user\@$device_ip");

        my $sqr_update = $dbh->prepare("update devices set last_update_time='$time_now_str' where id=$device_id");
        $sqr_update->execute();
        $sqr_update->finish();
    }

    &log_process("copy new key pair to $sshprivatekey & $sshpublickey");
    copy(("/opt/freesvr/audit/sshgw-audit/keys/pvt_new/". basename $sshprivatekey), $sshprivatekey);
    copy(("/opt/freesvr/audit/sshgw-audit/keys/pub_new/". basename $sshpublickey), $sshpublickey);
    &log_process("finish copy new key pair to $sshprivatekey & $sshpublickey");
}

$dbh->disconnect();

sub scp_to_remote
{
    my($device_ip,$user,$port,$sshprivatekey,$authorized_key) = @_;
    my $cmd = "scp -i $sshprivatekey -P $port $authorized_key $user\@$device_ip:~/.ssh/authorized_keys";
    &log_process("scp authorized_key by $cmd");
    if(system($cmd) != 0)
    {
        &log_process("scp authorized_key for $device_ip, user: $user error");
    }
}

sub modify_authorized_key
{
    my($device_id,$pubkey,$authorized_key) = @_;

    my @cache;
    open(my $fd_fr, "<$authorized_key");
    while(my $line = <$fd_fr>)
    {
        chomp $line;
        if((split /\s+/,$line)[2] eq $device_id)
        {
            $line = "$pubkey $device_id";
        }
        push @cache,$line;
    }
    close $fd_fr;

    open(my $fd_fw, ">$authorized_key");
    foreach my $line(@cache)
    {
        print $fd_fw $line,"\n";
    }
    close $fd_fw;
}

sub get_pub_key
{
    my($pub_key_file) = @_;
    my $pubkey = "";
    open(my $fd_fr, "<$pub_key_file");
    while(my $line = <$fd_fr>)
    {
        chomp $line;
        $pubkey = $line;
    }
    close $fd_fr;
    return $pubkey;
}

sub generate_keys
{
    my($key_file) = @_;

    if(system("ssh-keygen -t rsa -N \"\" -C \"\" -f /tmp/$key_file") != 0)
    {
        &log_process("ssh-keygen error for $key_file");
        foreach my $file(glob "$key_file"."*")
        {
            unlink $file;
        }
        return 1;
    }
    &log_process("generate ssh key in /tmp/$key_file");
    return 0;
}

sub init_env
{
    unless(-e "/opt/freesvr/audit/sshgw-audit/keys/pvt_old")
    {
        `mkdir -p /opt/freesvr/audit/sshgw-audit/keys/pvt_old`;
    }

    unless(-e "/opt/freesvr/audit/sshgw-audit/keys/pvt_new")
    {
        `mkdir -p /opt/freesvr/audit/sshgw-audit/keys/pvt_new`;
    }

    unless(-e "/opt/freesvr/audit/sshgw-audit/keys/pub_old")
    {
        `mkdir -p /opt/freesvr/audit/sshgw-audit/keys/pub_old`;
    }

    unless(-e "/opt/freesvr/audit/sshgw-audit/keys/pub_new")
    {
        `mkdir -p /opt/freesvr/audit/sshgw-audit/keys/pub_new`;
    }

    unless(-e "/opt/freesvr/audit/sshgw-audit/keys/backups")
    {
        `mkdir -p /opt/freesvr/audit/sshgw-audit/keys/backups`;
    }

    unless(-e "/opt/freesvr/audit/sshgw-audit/keys/authorized_keys")
    {
        &log_process("authorized_keys for authorized_keys not exists");
        exit 1;
    }

    &log_process("backup pvt keys to /opt/freesvr/audit/sshgw-audit/keys/backups");
    if(system("zip -qrj '/opt/freesvr/audit/sshgw-audit/keys/backups/pvt-$time_now_str.zip' '/opt/freesvr/audit/sshgw-audit/keys/pvt'") != 0)
    {
        &log_process("backup pvt keys error");
        exit 1;
    }
    &log_process("finish backup pvt keys to /opt/freesvr/audit/sshgw-audit/keys/backups");

    &log_process("backup pub keys to /opt/freesvr/audit/sshgw-audit/keys/backups");
    if(system("zip -qrj '/opt/freesvr/audit/sshgw-audit/keys/backups/pub-$time_now_str.zip' '/opt/freesvr/audit/sshgw-audit/keys/pub'") != 0)
    {
        &log_process("backup pub keys error");
        exit 1;
    }
    &log_process("finish backup pub keys to /opt/freesvr/audit/sshgw-audit/keys/backups");

    &log_process("backup authorized_keys to /opt/freesvr/audit/sshgw-audit/keys/backups");
    if(system("zip -qrj '/opt/freesvr/audit/sshgw-audit/keys/backups/authorized_keys-$time_now_str.zip' '/opt/freesvr/audit/sshgw-audit/keys/authorized_keys'") != 0)
    {
        &log_process("backup authorized_keys error");
        exit 1;
    }
    &log_process("finish backup authorized_keys to /opt/freesvr/audit/sshgw-audit/keys/backups");
}

sub check_modify
{
    my($last_update_time,$month,$week,$user_define) = @_;
    my $interval = $time_now_utc - $last_update_time;

    if(defined $month && $month!=0 && $interval>27*3600)
    {
        return 1;
    }

    if(defined $week && $week!=0 && $interval>7*3600)
    {
        return 1;
    }

    if(defined $user_define && $user_define!=0 && $interval>$user_define*3600)
    {
        return 1;
    }
    return 0;
}

sub log_process
{
    my($log) = @_;
    print $log,"\n";
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
