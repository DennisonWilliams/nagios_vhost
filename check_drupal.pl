#!/usr/bin/perl -w
#use strict;
use Nagios::Plugin;
use Data::Dumper;
use File::Basename;

my $drush = '/usr/bin/drush ';
my $VERSION = '0.1';
my $np = Nagios::Plugin->new(
  usage => "Usage: %s [ -v|--verbose ] [ -p|--path ]",
  version => $VERSION,
  plugin => "Check Drupal",
  shortname => "Check Drupal",
  timeout => 15,
);

$np->add_arg(
  spec => 'path|p=s',
  help => "--path=STRING\n  Path to the drupal installation, Defaults to CWD",
  required => 0
);

$np->getopts;

alarm $np->opts->timeout;

my $path = $np->opts->path?$np->opts->path:`pwd`;
print "running $drush -r $path ups\n"
		if $np->opts->verbose;

#open (DRUSH, $drush . '-r ' . $path .' ups 2>/dev/null | grep -v SEC |') 
open (DRUSH, $drush . '-r ' . $path .' ups 2>/dev/null |') 
#open (DRUSH, $drush . '-r ' . $path .' ups |') 
	or die "Could not run $drush";
my ($security_updates, $updates);
while (<DRUSH>) {
	#next unless /^\s([A-Za-z ]+)\s*([\d.-]+)\s+([\d.-]+)\s*(.*)$/;
	next unless /^\s([A-Za-z \(\)_]+)\s*([\d.-A-Za-z]+)\s*([\d.-A-Za-z]+)\s*(.*)$/;
	my $module = $1;
	my $installed = $2;
	my $proposed = $3;
	my $message = $4;
	$module =~ s/\s+$//;
	next if ($module =~ /Name/);
	if ($message =~ /security/i) {
		$np->add_message(CRITICAL, "$module ($installed < $proposed)");
	} else {
		$np->add_message(WARNING, "$module ($installed < $proposed)");
	}

	print "module=$module, installed=$installed, proposed=$proposed, message=$message\n"
		if $np->opts->verbose;
}

close DRUSH;

$np->nagios_exit($np->check_messages());
