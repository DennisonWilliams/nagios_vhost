#!/usr/bin/perl

# make sure nagios is running
`ps -ef|grep nagios3|grep -v grep|grep -q nagios3`;
$nagios_is_running = $??0:1;

print "Nagios is not running\n"
	if $nagios_is_running;

# kill nagios_vhost if it is running
my $pid = `ps -ef|grep nagios_vhost|grep -v grep|grep daemon|awk '{print \$2}'`;
chomp $pid;
print "nagios_vhost.pl is not running\n"
	unless $pid;

kill(TERM, $pid) if $pid;

# start nagios_vhost
`/usr/bin/perl /home/radicaldesigns/src/nagios_vhost/nagios_vhost.pl --daemon`;

my $pid = `ps -ef|grep nagios_vhost|grep -v grep|grep daemon|awk '{print \$2}'`;
chomp $pid;
print "nagios_vhost.pl did not start\n" unless $pid;
