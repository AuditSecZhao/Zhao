#!/usr/bin/perl
use warnings;
use strict;
use DBI;
use DBD::mysql;

our $mysql_user = "freesvr";
our $mysql_passwd = "freesvr";

our @backup_files = qw#
/opt/freesvr/audit/gateway/log/telnet/
/opt/freesvr/audit/gateway/log/ssh/
/opt/freesvr/audit/gateway/log/rdp/
/opt/freesvr/audit/ftp-audit/backup/upload/
/opt/freesvr/audit/ftp-audit/backup/download/
/opt/freesvr/audit/log/sftp/
#;

our %local_database;
our %all_tables;

our $dbh=DBI->connect("DBI:mysql:database=audit_nm;host=localhost;mysql_connect_timeout=5","root","",{RaiseError=>1});
my $utf8 = $dbh->prepare("set names utf8");
$utf8->execute();
$utf8->finish();

&init_database();
&init_tables();

my $sqr_select = $dbh->prepare("select host from device_mysql_info");
$sqr_select->execute();
while(my $ref_select = $sqr_select->fetchrow_hashref())
{
	my $host = $ref_select->{"host"};

	unless($host eq "localhost")
	{
		&mysql_backup($host);
		&file_backup($host);
	}
}
$sqr_select->finish();
$dbh->disconnect();

sub init_database
{
	my $sqr_select = $dbh->prepare("show databases");
	$sqr_select->execute();
	while(my $ref_select = $sqr_select->fetchrow_arrayref())
	{
		my $database = $ref_select->[0];
		unless(exists $local_database{$database})
		{
			$local_database{$database} = 1;
		}
	}
}

sub init_tables
{
	my @tables = qw/
		admin_log                              
		alarm                                  
		appcomm                                
		appdevices                             
		appgroup                               
		appicon                                
		applogin                               
		appmember                              
		appprogram                             
		apppserver                             
		apppub                                 
		appresourcegroup                       
        commands
		devices                                
		forbidden_commands                     
		forbidden_commands_groups              
		forbidden_commands_user                
		forbidden_groups                       
		ftpcomm                                
		ftpsessions                            
		lgroup                                 
		lgroup_appresourcegrp                  
		lgroup_devgrp                          
		lgroup_resourcegrp                     
		login4approve                          
		login_tab                              
		login_template                         
		loginacct                              
		loginacctcode                          
		logincommit                            
		loginlog                               
		luser                                  
		luser_appresourcegrp                   
		luser_devgrp                           
		luser_resourcegrp                      
		member                                 
		rdpsessions                            
		servergroup                            
		servers                                
		sessions                               
		setting                                
		sftpcomm                               
		sftpsessions
		/;

	foreach my $table(@tables)
	{
		unless(exists $all_tables{$table})
		{
			$all_tables{$table} = 1;
		}
	}
}

sub mysql_backup
{
	my($host) = @_;

	my @remote_tables = &get_tables($host);

	my $db_name = $host;
	$db_name =~ s/\./_/g;

	if(exists $local_database{$db_name})
	{
		my $sqr_drop = $dbh->prepare("drop database $db_name");
		$sqr_drop->execute();
		$sqr_drop->finish();
	}

	my $sqr_create = $dbh->prepare("create database $db_name");
	$sqr_create->execute();
	$sqr_create->finish();

	my $cmd = "mysqldump -h $host -u $mysql_user -p$mysql_passwd audit_sec ".join(" ",@remote_tables)." > /tmp/remote_bk.sql";
	if(system($cmd))
	{
		print "$host mysqldump cmd error\n";
		unlink "/tmp/remote_bk.sql";
		return;
	}

	$cmd = "mysql -h localhost -u root $db_name</tmp/remote_bk.sql";
	if(system($cmd))
	{
		print "$host mysql cmd error\n";
	}

	unlink "/tmp/remote_bk.sql";
	return;
}

sub get_tables
{
	my($host) = @_;
	my @tmp_tables;

	my $remote_dbh = DBI->connect("DBI:mysql:database=audit_sec;host=$host;mysql_connect_timeout=5","$mysql_user","$mysql_passwd",{RaiseError=>0});
	my $utf8 = $remote_dbh->prepare("set names utf8");
	$utf8->execute();
	$utf8->finish();

	my $sqr_select = $remote_dbh->prepare("show tables");
	$sqr_select->execute();
	while(my $ref_select = $sqr_select->fetchrow_arrayref())
	{
		my $table = $ref_select->[0];
		if(exists $all_tables{$table})
		{
			push @tmp_tables,$table;
		}
	}
	$remote_dbh->disconnect();
	return @tmp_tables;
}

sub file_backup
{
	my($host) = @_;
	my $dst_path = "/opt/${host}_bk/";

	unless(-e $dst_path)
	{
		mkdir $dst_path,0755;
	}

	foreach my $file(@backup_files)
	{
		$file =~ s/\/$//;
		my $cmd = "rsync -aq -e 'ssh -p 2288' root\@$host:$file $dst_path";

		if($cmd =~ /ftp-audit/)
		{
			$cmd .= "ftp/";
		}

		if(system($cmd))
		{
			print "$file backup to $host failed\n";
		}
	}
}
