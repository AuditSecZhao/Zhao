#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use DBD::mysql;
use Crypt::CBC;
use MIME::Base64;

our($file_start_time,$file_end_time,@protocols) = @ARGV;

our $audit_sec_date = 10000;
our $log_date = 10;
our $cacti_date = 10;
our $dbaudit_date = 10;
our @del_dirs;

our($mysql_user,$mysql_passwd) = &get_local_mysql_config();
our $dbh=DBI->connect("DBI:mysql:database=audit_sec;host=localhost;mysql_connect_timeout=120",$mysql_user,$mysql_passwd,{RaiseError=>1});
our $utf8 = $dbh->prepare("set names utf8");
$utf8->execute();
$utf8->finish();

&pro_process();

&file_del();
#&database_del();
exit 0;

sub pro_process
{
    if(defined $file_start_time && defined $file_end_time && scalar @protocols != 0)
    {
        if($file_start_time =~ /^\d{4}-\d{1,2}-\d{1,2}/)
        {
            my($year,$mon,$day) = split /-/,$file_start_time;
            ($mon,$day) =  (sprintf("%02d", $mon),sprintf("%02d", $day));
            $file_start_time = $year.$mon.$day;
        }
        else
        {
            print "start time format err\n";
            exit 1;
        }

        if($file_end_time =~ /^\d{4}-\d{1,2}-\d{1,2}/)
        {
            my($year,$mon,$day) = split /-/,$file_end_time;
            ($mon,$day) =  (sprintf("%02d", $mon),sprintf("%02d", $day));
            $file_end_time = $year.$mon.$day;
        }
        else
        {
            print "end time format err\n";
            exit 1;
        }

        foreach my $protocol(@protocols)
        {
            if($protocol eq "telnet" || $protocol eq "all")
            {
                push @del_dirs,"/opt/freesvr/audit/gateway/log/telnet/cache";
                push @del_dirs,"/opt/freesvr/audit/gateway/log/telnet/replay";
            }

            if($protocol eq "ssh" || $protocol eq "all")
            {
                push @del_dirs,"/opt/freesvr/audit/gateway/log/ssh/cache";
                push @del_dirs,"/opt/freesvr/audit/gateway/log/ssh/replay";
            }

            if($protocol eq "rdp" || $protocol eq "all")
            {
                push @del_dirs,"/opt/freesvr/audit/gateway/log/rdp/replay";
                push @del_dirs,"/opt/freesvr/audit/gateway/log/rdp/key";
            }
            
            if($protocol eq "ftp" || $protocol eq "all")
            {
                push @del_dirs,"/opt/freesvr/audit/ftp-audit/backup/upload/";
                push @del_dirs,"/opt/freesvr/audit/ftp-audit/backup/download/";
            }

            if($protocol eq "sftp" || $protocol eq "all")
            {
                push @del_dirs,"/opt/freesvr/audit/log/sftp/download";
                push @del_dirs,"/opt/freesvr/audit/log/sftp/upload";
            }
        }

        if(scalar @del_dirs == 0)
        {
            print "protocol 错误\n";
            exit 1;
        }
    }
    else
    {
        my $sqr_select = $dbh->prepare("select svalue from setting where sname = 'autodelete'");
        $sqr_select->execute();
        my $ref_select = $sqr_select->fetchrow_hashref();
        my $interval = $ref_select->{"svalue"};
        $sqr_select->finish();

        unless(defined $interval)
        {
            print "setting 表中没有 autodelete 配置\n";
            exit 1;
        }

#        $file_end_time = time;
#        $file_start_time = $file_end_time - $interval * 3600 * 24;
        $file_end_time = time - $interval * 3600 * 24;
        $file_start_time = 0;

        my($year,$mon,$day) = (localtime $file_start_time)[5,4,3];
        ($year,$mon,$day) =  ($year+1900,sprintf("%02d", $mon+1),sprintf("%02d", $day));
        $file_start_time = $year.$mon.$day;

        ($year,$mon,$day) = (localtime $file_end_time)[5,4,3];
        ($year,$mon,$day) =  ($year+1900,sprintf("%02d", $mon+1),sprintf("%02d", $day));
        $file_end_time = $year.$mon.$day;

        @del_dirs = (
                "/opt/freesvr/audit/gateway/log/telnet/cache/",
                "/opt/freesvr/audit/gateway/log/telnet/replay/",
                "/opt/freesvr/audit/gateway/log/ssh/cache/",
                "/opt/freesvr/audit/gateway/log/ssh/replay/",
                "/opt/freesvr/audit/gateway/log/rdp/replay/",
                "/opt/freesvr/audit/gateway/log/rdp/key/",
                "/opt/freesvr/audit/ftp-audit/backup/upload/",
                "/opt/freesvr/audit/ftp-audit/backup/download/",
                "/opt/freesvr/audit/log/sftp/download/",
                "/opt/freesvr/audit/log/sftp/upload/",
                );
    }

    print "$file_start_time\t$file_end_time\n";
    print join("\n",@del_dirs),"\n";
}

sub file_del
{
    foreach my $del_dir(@del_dirs)
    {
        $del_dir =~ s/\/$//;
        unless(-e $del_dir)
        {
            next;
        }

        opendir(my $dir,$del_dir);
        foreach my $file(readdir $dir)
        {
            unless($file =~ /^\d{4}-\d{1,2}-\d{1,2}/)
            {
                next;
            }

            my($year,$mon,$day) = split /-/,$file;
            ($mon,$day) =  (sprintf("%02d", $mon),sprintf("%02d", $day));
            my $file_time = $year.$mon.$day;

            if($file_time > $file_start_time && $file_time < $file_end_time)
            {
                $file = "$del_dir/$file";
                print $file,"\n";
                `rm -fr $file`;
            }
        }
        closedir $dir;
    }
}

sub database_del
{
    my $sqr_database = $dbh->prepare("show databases");
    $sqr_database->execute();
    while(my $ref_database = $sqr_database->fetchrow_arrayref())
    {
        if($ref_database->[0] eq "audit_sec")
        {
            &audit_sec_process("audit_sec");
        }
        elsif($ref_database->[0] eq "log")
        {
            &log_process("log");
        }
        elsif($ref_database->[0] eq "cacti")
        {
            &cacti_process("cacti");
        }
        elsif($ref_database->[0] eq "dbaudit")
        {
            &dbaudit_process("dbaudit");
        }
    }
    $sqr_database->finish();
}

sub delete_func
{
    my($database_name,$table_name,$col_name,$interval) = @_;

    my $sqr_delete = $dbh->prepare("delete from $database_name.$table_name where date($col_name) < date_sub(curdate(),interval $interval day)");
    $sqr_delete->execute();
    $sqr_delete->finish();
}

sub audit_sec_process
{
    my($database_name) = @_;
    my %table_name;

    my $sqr_table = $dbh->prepare("show tables from $database_name");
    $sqr_table->execute();
    while(my $ref_table = $sqr_table->fetchrow_arrayref())
    {
        $table_name{$ref_table->[0]} = 1;
    }
    $sqr_table->finish();

    my %table_col = ("snmp_status" => "datetime",
            "tcp_port_value" => "datetime",
            "status" => "datetime",
            "tcp_port_alarm" => "datetime",
            );

    foreach my $key(keys %table_col)
    {
        if(exists $table_name{$key})
        {
            &delete_func($database_name,$key,$table_col{$key},$audit_sec_date);
        }
    }
}

sub log_process
{
    my($database_name) = @_;
    my %table_name;

    my $sqr_table = $dbh->prepare("show tables from $database_name");
    $sqr_table->execute();
    while(my $ref_table = $sqr_table->fetchrow_arrayref())
    {
        $table_name{$ref_table->[0]} = 1;
    }
    $sqr_table->finish();

    my %table_col = ("eventlogs" => "datetime",
            "windows_login" => "starttime",
            "countlogs_minuter_server" => "date",
            "countlogs_minuter_level" => "date",
            "countlogs_minuter_detailed" => "date",
            "countlogs_hour_server" => "date",
            "countlogs_hour_level" => "date",
            "countlogs_hour_detailed" => "date",
            "login_day_count" => "date",
            "logs" => "datetime",
            "linux_login" => "starttime",
            "alllogs" => "datetime"
            );

    foreach my $key(keys %table_col)
    {
        if(exists $table_name{$key})
        {
            &delete_func($database_name,$key,$table_col{$key},$log_date);
        }
    }
}

sub cacti_process
{
    my($database_name) = @_;
	my %table_name;

	my $sqr_table = $dbh->prepare("show tables from $database_name");
	$sqr_table->execute();
	while(my $ref_table = $sqr_table->fetchrow_arrayref())
	{
		$table_name{$ref_table->[0]} = 1;
	}
	$sqr_table->finish();

	my %table_col = ("snmp_status" => "datetime",
			"tcp_port_value" => "datetime",
			"status" => "datetime",
			"tcp_port_alarm_group" => "datetime",
			);

	foreach my $key(keys %table_col)
	{  
		if(exists $table_name{$key})
		{
			&delete_func($database_name,$key,$table_col{$key},$cacti_date);
		}
	}  
}

sub dbaudit_process
{
	my($database_name) = @_;
	my %table_name;

	my $sqr_table = $dbh->prepare("show tables from $database_name");
	$sqr_table->execute();
	while(my $ref_table = $sqr_table->fetchrow_arrayref())
	{
		$table_name{$ref_table->[0]} = 1;
	}
	$sqr_table->finish();

	my %table_col = ("oracle_sessions" => "start",
			"oracle_commands" => "at",
			"sybase_sessions" => "start",
			"sybase_commands" => "at",
			"mysql_sessions" => "start",
			"mysql_commands" => "at",
			"db2_sessions" => "start",
			"db2_commands" => "at",
			"sqlserver_sessions" => "start",
			"sqlserver_commands" => "at",
			);

	foreach my $key(keys %table_col)
	{  
		if(exists $table_name{$key})
		{
			&delete_func($database_name,$key,$table_col{$key},$dbaudit_date);
		}
	}  
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
