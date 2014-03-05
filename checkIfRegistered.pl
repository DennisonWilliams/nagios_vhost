#!/usr/bin/perl
use strict;
use warnings;
use Cwd 'abs_path';
use File::Basename;
use DBI;
use Data::Dumper;
use Net::DNS;
use Net::XWhois;

my $DBFILE = dirname(abs_path($0)) .'/.nagios_vhost.pl.db';
my $DBH = DBI->connect("dbi:SQLite:dbname=$DBFILE", "", "",{ 
	RaiseError => 1,
	sqlite_use_immediate_transaction => 1 })
		|| die "Could not connect to database: $DBI::errstr";

my $sth = $DBH->prepare('
	SELECT host.name as host_name,vhost.name as vhost_name,vhost_alias.name as vhost_alias_name, vhost.ip as ip 
	FROM host
	LEFT join vhost on (host.host_id = vhost.host_id)
	LEFT join vhost_alias on (vhost.vhost_id = vhost_alias.vhost_id)
');

my %state;
my $ct = 0;
$sth->execute();
while (my $row = $sth->fetchrow_hashref()) {

	foreach my $name (qw/vhost_name vhost_alias_name/) {
		if (!$state{$row->{$name}}) {
			$state{$row->{$name}} = 1;
			my $res = Net::DNS::Resolver->new;
			my $query = $res->search($row->{$name});
			my $ip;
			if ($query) {
				foreach my $rr ($query->answer) {
					next unless $rr->type eq "A" || $rr->type eq "CNAME";
					$ip = $rr->address;

					print "Server: ". $row->{'host_name'} .", vhost: ". $row->{$name} ." (". 
						$row->{'ip'} .') has a a new ip: '. $ip ."\n"
						if ($ip ne $row->{'ip'});
				}
			} else {
				print "Server: ". $row->{'host_name'} .", vhost: ". $row->{$name} ." (". 
					$row->{'ip'} .") no longer has an ip in DNS.\n";
			}
		}
	}
	$ct++;
}
print "$ct\n";
