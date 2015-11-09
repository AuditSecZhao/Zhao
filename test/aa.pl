#!/usr/bin/perl
use warnings;
use strict;
use File::HomeDir;
use Expect;

my $device_ip = '172.16.210.249';
my $username = 'root';
my $passwd = 'freesvr123';
my $port = 2288;
my $version = "-1";

my $exp = Expect->new;
$exp->log_stdout(0);
$exp->debug(0);

my $flag = &cisco_ssh_process($exp,$device_ip,$version,$username,$passwd,$port);
print "$flag\n";

sub cisco_ssh_process
{
    my($exp,$device_ip,$version,$username,$passwd,$port) = @_;

    my $count = 0;
    my $flag = 1;

    while($count < 10 && $flag == 1)
    {
        ++$count;

        print "ssh $version -l $username $device_ip -p $port\n";
        $exp->spawn("ssh $version -l $username $device_ip -p $port");

        my @results = $exp->expect(20,
                [
                qr/~\]/i,
                sub {
                $flag = 0;
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
                    $flag = &rsa_err_process($username,$device_ip);
                }
        ],
            );

        print $flag,"\n";
        if($flag == 0)
        {
            return 1;
        }
        elsif($flag != 1)
        {
            return 0;
        }
    }
}

sub rsa_err_process
{
    my($user,$ip) = @_;
    my $home = File::HomeDir->users_home($user);
    unless(defined $home)
    {
        print "cant find home dir for user $user\n";
        return 2;
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

    return 1;
}
