#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use DBD::mysql;
use Getopt::Long;
use File::Copy;
use File::Basename;
use Mail::Sender;
use Encode;
use String::MkPasswd qw(mkpasswd);
use Crypt::CBC;
use MIME::Base64;

=pod
my $maxrepeat = 4;
my $mindiff = 4;
my $old_passwd = "7Bwkb[gd";
#my $passwd = "asgaeesyhwy";
my $passwd = undef;
if(defined $passwd)
{
    my $ret = &check_passwd($passwd,$old_passwd);
    if($ret!=0)
    {
        print "$passwd is not ok\n";
    }
}
else
{
    $passwd = &random_passwd();
}

sub random_passwd
{
    my $passwd = undef;
    my $check_ret = 1;
    while(!defined $passwd || $check_ret)
    {
        $passwd = mkpasswd(
            -length     => 8,
            -minnum     => 1,
            -minlower   => 3,
            -minupper   => 1,
            -minspecial => 1,
        );
        print $passwd,"\n";

        $check_ret = &check_passwd($passwd,$old_passwd);
    }
}

sub check_passwd
{
    my($new_passwd,$old_passwd) = @_;

    my %new_hash;
    my %old_hash;
    my @chars = unpack("C*",$new_passwd);
    foreach my $char(@chars)
    {
        unless(exists $new_hash{$char})
        {
            $new_hash{$char} = 0;
        }
        ++$new_hash{$char};
    }

    my $max=0;
    foreach my $key(keys %new_hash)
    {
        if($max==0 || $new_hash{$key}>$max)
        {
            $max = $new_hash{$key};
        }
    }

    if($max >= $maxrepeat)
    {
        return 1;
    }

    @chars = unpack("C*",$old_passwd);
    foreach my $char(@chars)
    {
        unless(exists $old_hash{$char})
        {
            $old_hash{$char} = 0;
        }
        ++$old_hash{$char};
    }

    my $diff = 0;
    foreach my $key(keys %new_hash)
    {
        unless(exists $old_hash{$key})
        {
            ++$diff;
        }
    }

    if($diff < $mindiff)
    {
        return 1;
    }

    return 0;
}
=cut

&send_mail("wxl890206\@126.com","1。2.3.5 i asga 密码信息", "1。2.3.5 i asga 密码信息","smtp.163.com", "testnetmwd\@163.com", "netmwd123");
#&send_mail("965792145\@qq.com","1.2.3.4 密码信息", "1。2.3.5 i asga 密码信息","smtp.163.com", "testnetmwd\@163.com", "netmwd123");

sub send_mail
{   
    my($mailto,$subject,$msg,$mailserver,$mailfrom,$mailpwd) = @_;
    
    my $sender = new Mail::Sender;
#   $subject = encode_mimewords($subject,'Charset','UTF-8');
    $subject =  encode("gb2312", decode("utf8", $subject));           #freesvr 专用
#   $msg = encode_mimewords($msg,'Charset','gb2312');
        $msg =  encode("gb2312", decode("utf8", $msg));              #freesvr 专用
        
        if ($sender->MailFile({
                    smtp => $mailserver,
                    from => $mailfrom,
                    to => $mailto,
                    subject => $subject,
                    msg => $msg,
                    auth => 'LOGIN',
                    authid => $mailfrom,
                    authpwd => $mailpwd,
                    file => '../a.tgz',
                    b_charset => 'gb2312',
#               encoding => 'gb2312',
                    })<0){
            return 2;
        }
        else
        {
            return 1;
        }
}
