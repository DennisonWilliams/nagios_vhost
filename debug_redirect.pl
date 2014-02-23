#!/usr/bin/perl
use WWW::Mechanize;
use Getopt::Long;
use Log::Log4perl qw(get_logger :levels);

my ($VHOST, $IP);
my $result = GetOptions (
	"vhost:s" => \$VHOST,
	"ip:s"    => \$IP
);

if (!$VHOST) {
	print "--vhost <vhost> needs to be specified\n";
	exit;
}

my $mech = WWW::Mechanize->new(
	ssl_opts => { 
		verify_hostname => 0
	} 
);

my $appender = Log::Log4perl::Appender->new(
	"Log::Log4perl::Appender::Screen",
);

our $LOGGER = get_logger($0);
$LOGGER->add_appender($appender);
$LOGGER->level($DEBUG);

$mech->add_handler('response_redirect' => \&response_redirect);
my $get = $VHOST;
$mech->add_header(HOST => $VHOST);
if ($IP) {
	$get = $IP;
}

# This should automatically handle redirects
eval {
	$LOGGER->debug("http://$get ($VHOST)");
	$mech->get("http://$get");
};
if ($@) {
	$LOGGER->error("Issues: $@. $get");
}

$LOGGER->debug("http://$get returned: ". $mech->response()->code());

# We actually want to stay on the same server so we only chnage the HOST
# and the path.
# If the handler returns an HTTP::Request object we'll start over with processing this request instead.
sub response_redirect {
	my($response, $ua, $h) = @_;

	my $url;
	if ($response->header('Location')) {
		$response->request()->as_string() =~ /GET\s+(http[^:]*):\/\/([^\/\s]+)/;
		my $http = $1;
		my $ip = $2;
		$LOGGER->debug("response_redirect() request header: ". $response->request()->as_string());
		$LOGGER->debug("response_redirect() recived Location header: ". $response->header('Location'));
		$LOGGER->debug("response_redirect() response header: ". $response->as_string());
		if ($response->header('Location') !~ /^http/) {
			$url = $http .'://'. $ip;
			if ($response->header('Location') !~ /^\//) {
				$url .= "/";
			}
			$url .= $response->header('Location');
		} else {
			$response->header('Location') =~ /(http[^:]*):\/\/([^\/]+)(\/.*)?/;
			$LOGGER->debug("response_redirect() HOST header: $2");
			$ua->add_header(HOST => $2);
			$url = $1 .'://'. $ip . $3;
		}

		$LOGGER->debug("response_redirect() new url: $url");

		# Update the uri with the Location Header value
		# create and return a HTTP::Request object
		# TODO: is there ever a situation where this would not be a GET?
		# The optional $header argument should be a reference to an "HTTP::Headers" 
		# object or a plain array reference of key/value pairs.
		return HTTP::Request->new( "GET", $url);
	}
	return;
}
