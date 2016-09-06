#!/usr/bin/perl -w
use Env;
use lib "$HOME/perl5/lib/perl5";
#use strict;
use Nagios::Plugin "0.36";
use Data::Dumper;
use File::Basename;
use JSON;

# This has to be in the users path
my $wp = 'wp ';
my $VERSION = '0.1';
my $np = Nagios::Plugin->new(
  usage => "Usage: %s [ -v|--verbose ] [ -p|--path ]",
  version => $VERSION,
  plugin => "Check WordPress",
  shortname => "Check WordPress",
  timeout => 15,
);

$np->add_arg(
  spec => 'path|p=s',
  help => "--path=STRING\n  Path to the WordPress installation, Defaults to CWD",
  required => 0
);

$np->getopts;

alarm $np->opts->timeout;

my $json = JSON->new;
$json->relaxed([1]);

my $path = $np->opts->path?$np->opts->path:`pwd`;
chomp $path;

my $wp_check_core_version = "$wp --path=$path core version";
my $wp_check_core_update = "$wp --format=json --path=$path core check-update";
my $wp_check_plugin_update = "$wp --format=json --path=$path --dry-run --all plugin update ";

print "Checking WordPress core version: $wp_check_core_version\n"
  if $np->opts->verbose;
open (WP, $wp_check_core_version .' 2>&1 |') or die "Could not run $wp_check_core_version";
my $installed_core;
while (my $line = <WP>) {
	# If it starts with a number we assume it is the version and bail
	if ($line =~ /^\d/) {
		$installed_core = $line;
		last;
	} elsif ( $line =~ /^Error: (.*)$/ ) {
		$np->nagios_exit(CRITICAL, "Things didnt start well: $1");
	}
}

close WP;
chomp $installed_core;

print "Checking WordPress core updates: $wp_check_core_update\n"
  if $np->opts->verbose;
open (WP, $wp_check_core_update .' 2>&1 |') or die "Could not run $wp_check_core_update";
my $jsonText;
while (my $line = <WP>) {
        $jsonText .= $line;
	$np->nagios_exit(CRITICAL, "Its not going to work out between us: $1")
		if $line =~ /Error: (.*)/;
}
close WP;

# If $jsonText2 is empty it could also be because there are not updates
# TODO: Verify this is not needed
# if ($jsonText =~ m/Fatal error/s) { 
if ($jsonText && $jsonText =~ /Fatal error/) {
  $np->add_message(CRITICAL, "Running '$wp_check_core_update' returned an error.");
  $jsonText = '';
} elsif ( $jsonText && $jsonText =~ m/([^\[]*)([\[].*)$/s ) {
	# Its possible there is a bunch of warning messages at the begining
	$jsonText = $2;
}
goto CHECKPLUGINS if !$jsonText;

my $updates = $json->decode($jsonText);
my $core_updates;
my $severity = OK;
#print Dumper($jsonText);
#print Dumper($updates); exit;
foreach my $update (keys @$updates) {
        $core_updates .=', ' if $core_updates;
        $core_updates .= $update->{version}?$update->{version}:'';
}
$np->add_message(CRITICAL, "Core ". $installed_core ." < (". $core_updates .") ")
  if $core_updates;

$jsonText ='';
print "Checking WordPress plugin updates: $wp_check_plugin_update\n"
  if $np->opts->verbose;
CHECKPLUGINS: open (WP, $wp_check_plugin_update .' 2>&1|') 
  or die "Could not run $wp_check_plugin_update";

while (my $line = <WP>) {
        $jsonText .= $line;
}
close WP;

# If $jsonText2 is empty it could also be because there are not updates
if ($jsonText =~ /Fatal error/) {
  $np->add_message(CRITICAL, "Running '$wp_check_plugin_update' returned an error.");
  $jsonText = '';
} elsif ( $jsonText =~ m/Error: (.*)\n/s ) {
	$np->nagios_exit(CRITICAL, "Its not going to work out between us: $1");
} elsif ( $jsonText =~ m/([^\{\[]*)([\[\{].*)/s ) {
	# Its possible there is a bunch of warning messages at the begining
	$jsonText = $2;
}
goto EXIT if !$jsonText;

$jsonO = $json->decode($jsonText);
foreach my $update (@$jsonO) {
        my $plugin_updates .= $update->{name} .' ('.
          $update->{version} .' < '.
          $update->{update_version} .' )';
        $np->add_message(CRITICAL, $plugin_updates);
}

EXIT: $np->nagios_exit($np->check_messages());
