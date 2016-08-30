#!/usr/bin/perl -w
#use strict;
use Nagios::Plugin;
use Data::Dumper;
use File::Basename;
use JSON;

my $wp = '/usr/bin/wp ';
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
open (WP, $wp_check_core_version .'|') or die "Could not run $wp_check_core_version";
my $installed_core = <WP>;
close WP;
chomp $installed_core;

print "Checking WordPress core updates: $wp_check_core_update\n"
  if $np->opts->verbose;
open (WP, $wp_check_core_update .' 2>&1 |') or die "Could not run $wp_check_core_update";
my $jsonText;
while (my $line = <WP>) {
        $jsonText .= $line;
}
close WP;

# If $jsonText2 is empty it could also be because there are not updates
if ($jsonText =~ /Fatal error/) {
  $np->add_message(CRITICAL, "Running '$wp_check_core_update' returned an error.");
  $jsonText = '';
}
goto CHECKPLUGINS if !$jsonText;


my $jsonO = $json->decode($jsonText);
my $core_updates;
my $severity = OK;
foreach my $index (keys $jsonO) {
        $core_updates .=', ' if $core_updates;
        $core_updates .= $jsonO->[$index]->{version};
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
}
goto EXIT if !$jsonText;

$jsonO = $json->decode($jsonText);
foreach my $index (keys $jsonO) {
        my $plugin_updates .= $jsonO->[$index]->{name} .' ('.
          $jsonO->[$index]->{version} .' < '.
          $jsonO->[$index]->{update_version} .' )';
        $np->add_message(CRITICAL, $plugin_updates);
}

EXIT: $np->nagios_exit($np->check_messages());
