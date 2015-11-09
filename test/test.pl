#!/usr/bin/perl
use warnings;
use strict;
use RRDs;
use POSIX qw/ceil floor/;

my $start_time = time;
$start_time = (floor($start_time/60))*60;

my $file1 = "temp1.rrd";
if(! -e $file1)
{
	my $create_time = $start_time - 60;
	RRDs::create($file1,
			'--start', "$create_time",
			'--step', '60',
			'DS:val:GAUGE:120:U:U',
			'RRA:AVERAGE:0.5:1:576',
			'RRA:AVERAGE:0.5:12:168',
			'RRA:AVERAGE:0.5:288:35',
			'RRA:MAX:0.5:12:168',
			'RRA:MAX:0.5:288:35',
			'RRA:MIN:0.5:12:168',
			'RRA:MIN:0.5:288:35',
			);
}

my $file2 = "temp2.rrd";
if(! -e $file2)
{
	my $create_time = $start_time - 60;
	RRDs::create($file2,
			'--start', "$create_time",
			'--step', '60',
			'DS:val:GAUGE:60:U:U',
			'RRA:AVERAGE:0.5:1:576',
			'RRA:AVERAGE:0.5:12:168',
			'RRA:AVERAGE:0.5:288:35',
			'RRA:MAX:0.5:12:168',
			'RRA:MAX:0.5:288:35',
			'RRA:MIN:0.5:12:168',
			'RRA:MIN:0.5:288:35',
			);
}

RRDs::update(
		$file1,
		'-t', 'val',
		'--', join(':', "$start_time", '1'),
		);

RRDs::update(
		$file2,
		'-t', 'val',
		'--', join(':', "$start_time", '1'),
		);
