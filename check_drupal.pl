#!/usr/bin/perl -w
use Env;
use lib "$HOME/perl5/lib/perl5";
use Nagios::Plugin;
use Data::Dumper;
use File::Basename;
use JSON;
use POSIX;

my $drush = 'drush --format=json ';
my $VERSION = '0.1';
my $np = Nagios::Plugin->new(
  usage => "Usage: %s [ -v|--verbose ] [ -p|--path ] [ -u|--uri ]",
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

$np->add_arg(
  spec => 'uri|u=s',
  help => "--uri=STRING\n  URI of the target site",
  required => 0
);

$np->getopts;

alarm $np->opts->timeout;

my $json = JSON->new;
$json->relaxed([1]);

my $path = $np->opts->path?$np->opts->path:`pwd`;
print "running $drush -r $path ups\n"
		if $np->opts->verbose;

$drush .= "-r $path";
$drush .= " --uri=". $np->opts->uri
  if $np->opts->uri;
$drush .= " ups";
$drush .= " 2>&1";
$drush .= " |";

open (DRUSH, $drush) or die "Could not run $drush";
my $jsonText;
while (my $line = <DRUSH>) {
        $jsonText .= $line;
}
close DRUSH;

if ( $jsonText =~ /needs a higher bootstrap/) {
  my $user = POSIX::cuserid();
  $np->nagios_exit(UNKNOWN, "Could not run: $drush. Check that $user has permissions to settings.php.");
}

# Since we are capturing STDERR in the output, we need to filter it out here
$jsonText =~ m/^([^\{]*)(\{.*)$/s;
my $junk = $1;
my $jsonText2 = $2;

# If $jsonText2 is empty it could also be because there are not updates
$np->nagios_exit(OK, "") if ! $jsonText2;

my $jsonO = $json->decode($jsonText2);

foreach my $module (keys %{$jsonO}) {
	my $installed = $jsonO->{$module}->{'existing_version'};
	my $proposed = $jsonO->{$module}->{'recommended'};
	my $message = $jsonO->{$module}->{status_msg};
        my $severity = WARNING;

	if ($message =~ /security/i) {
                $severity = CRITICAL;
	} 
        $np->add_message($severity, "$module ($installed < $proposed)");

	print "module=$module, installed=$installed, proposed=$proposed, message=$message\n"
		if $np->opts->verbose;
}

$np->nagios_exit($np->check_messages());
