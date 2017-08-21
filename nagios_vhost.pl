#!/usr/bin/perl
use strict;
use warnings;
use DBI;
use Data::Dumper;
use Getopt::Long;
use File::Basename;
use Cwd 'abs_path';
use Net::SSH qw(ssh_cmd sshopen2 sshopen3);
use Net::DNS;
use Net::IP::Match::Regexp qw( create_iprange_regexp match_ip );

package Apache::ConfigParserWithFileHandle;
use Scalar::Util qw(openhandle);
use Apache::ConfigParser;
use Apache::ConfigParser::Directive      qw(DEV_NULL
                                            %directive_value_path_element_pos);
use Carp;
use Symbol;
our @ISA = ('Apache::ConfigParser');

# Overrides the Apache::ConfigParser::parse_file method to also include 
# file_handles
sub parse_file {
	my $INCORRECT_NUMBER_OF_ARGS = "passed incorrect number of arguments.\n";
  unless (@_ == 2) {
    confess "$0: Apache::ConfigParser::parse_file $INCORRECT_NUMBER_OF_ARGS";
  }

  my ($self, $file_or_dir_name) = @_;

  my @stat = stat($file_or_dir_name);
  unless (@stat) {
    $self->{errstr} = "cannot stat '$file_or_dir_name': $!";
    return;
  }

	my $fd;

  # If this is a real directory, than descend into it now.
  if (-d _) {
    unless (opendir(DIR, $file_or_dir_name)) {
      $self->{errstr} = "cannot opendir '$file_or_dir_name': $!";
      return;
    }
    my @entries = sort grep { $_ !~ /^\.{1,2}$/ } readdir(DIR);
    unless (closedir(DIR)) {
      $self->{errstr} = "closedir '$file_or_dir_name' failed: $!";
      return;
    }

    my $ok = 1;
    foreach my $entry (@entries) {
      $ok = $self->parse_file("$file_or_dir_name/$entry") && $ok;
      next;
    }

    if ($ok) {
      return $self;
    } else {
      return;
    }
  }

	elsif (-f _) {
		# Create a new file handle to open this file and open it.
		$fd = gensym;
		unless (open($fd, $file_or_dir_name)) {
			$self->{errstr} = "cannot open '$file_or_dir_name' for reading: $!";
			return;
		}
	}

	else {
		$fd = openhandle($file_or_dir_name);
		if (!defined($fd)) {
			$self->{errstr} = "The passed argument is not a file, directory, or a filehandle: $!";
			return;
		}
	}

  # Change the mode to binary to mode to handle the line continuation
  # match [^\\]\\[\r]\n.  Since binary files may be copied from
  # Windows to Unix, look for this exact match instead of relying upon
  # the operating system to convert \r\n to \n.
  binmode($fd);

  # This holds the contents of any previous lines that are continued
  # using \ at the end of the line.  Also keep track of the line
  # number starting a continued line for warnings.
  my $continued_line = '';
  my $line_number    = undef;

  # Scan the configuration file.  Use the file format specified at
  #
  # http://httpd.apache.org/docs/configuring.html#syntax
  #
  # In addition, use the semantics from the function ap_cfg_getline
  # in util.c
  # 1) Leading whitespace is first skipped.
  # 2) Configuration files are then parsed for line continuation.  The
  #    line continuation is [^\\]\\[\r]\n.
  # 3) If a line continues onto the next line then the line is not
  #    scanned for comments, the comment becomes part of the
  #    continuation.
  # 4) Leading and trailing whitespace is compressed to a single
  #    space, but internal space is preserved.
  while (<$fd>) {
    # Apache is not consistent in removing leading whitespace
    # depending upon the particular method in getting characters from
    # the configuration file.  Remove all leading whitespace.
    s/^\s+//;

    next unless length $_;

    # Handle line continuation.  In the case where there is only one \
    # character followed by the end of line character(s), then the \
    # needs to be removed.  In the case where there are two \
    # characters followed by the end of line character(s), then the
    # two \'s need to be replaced by one.
    if (s#(\\)?\\\r?\n$##) {
      if ($1)  {
        $_ .= $1;
      } else {
        # The line is being continued.  If this is the first line to
        # be continued, then note the starting line number.
        unless (length $continued_line) {
          $line_number = $.;
        }
        $continued_line .= $_;
        next;
      }
    } else {
      # Remove the end of line characters.
      s#\r?\n$##;
    }

    # Concatenate the continuation lines with this line.  Only update
    # the line number if the lines are not continued.
    if (length $continued_line) {
      $_              = "$continued_line $_";
      $continued_line = '';
    } else {
      $line_number    = $.;
    }

    # Collapse any ending whitespace to a single space.
    s#\s+$# #;

    # If there is nothing on the line, then skip it.
    next unless length $_;

    # If the line begins with </, then it is ending a context.
    if (my ($context) = $_ =~ m#^<\s*/\s*([^\s>]+)\s*>\s*$#) {
      # Check if an end context was seen with no start context in the
      # configuration file.
      my $mother = $self->{current_node}->mother;
      unless (defined $mother) {
        $self->{errstr} = "'$file_or_dir_name' line $line_number closes " .
                          "context '$context' which was never started";
        return;
      }

      # Check that the start and end contexts have the same name.
      $context               = lc($context);
      my $start_context_name = $self->{current_node}->name; 
      unless ($start_context_name eq $context) {
        $self->{errstr} = "'$file_or_dir_name' line $line_number closes " .
                          "context '$context' that should close context " .
                          "'$start_context_name'";
        return;
      }

      # Move the current node up to the mother node.
      $self->{current_node} = $mother;

      next;
    }

    # At this point a new directive or context node will be created.
    my $new_node = $self->{current_node}->new_daughter;
    $new_node->filename($file_or_dir_name);
    $new_node->line_number($line_number);

    # If the line begins with <, then it is starting a context.
    if (my ($context, $value) = $_ =~ m#^<\s*(\S+)\s+(.*)>\s*$#) {
      $context = lc($context);

      # Remove any trailing whitespace in the context's value as the
      # above regular expression will match all after the context's
      # name to the >.  Do not modify any internal whitespace.
      $value   =~ s/\s+$//;

      $new_node->name($context);
      $new_node->value($value);
      $new_node->orig_value($value);

      # Set the current node to the new context.
      $self->{current_node} = $new_node;

      next;
    }

		# Add comments 
		if (/^\s*#\s*(\S.*)$/) {
			my $comment = $1;
			$new_node->name('comment');
			$new_node->value($comment);
			next;
		}

    # Anything else at this point is a normal directive.  Split the
    # line into the directive name and a value.  Make sure not to
    # collapse any whitespace in the value.
    my ($directive, $value) = $_ =~ /^(\S+)(?:\s+(.*))?$/;
    $directive                   = lc($directive);

    $new_node->name($directive);
    $new_node->value($value);
    $new_node->orig_value($value);

    # If there is no value for the directive, then move on.
    unless (defined $value and length $value) {
      next;
    }

    my @values = $new_node->get_value_array;

    # Go through all of the value array elements for those elements
    # that are paths that need to be optionally pre-transformed, then
    # made absolute using ServerRoot and then optionally
    # post-transformed.
    my $value_path_index = $directive_value_path_element_pos{$directive};
    my @value_path_indexes;
    if (defined $value_path_index and $value_path_index =~ /^-?\d+$/) {
      if (substr($value_path_index, 0, 1) eq '-') {
        @value_path_indexes = (abs($value_path_index) .. $#values);
      } else {
        @value_path_indexes = ($value_path_index);
      }
    }

    for my $i (@value_path_indexes) {
      # If this directive takes a path argument, then make sure the path
      # is absolute.
      if ($new_node->value_is_path($i)) {
	# If the path needs to be pre transformed, then do that now.
	if (my $pre_transform_path_sub = $self->{pre_transform_path_sub}) {
	  my ($sub, @args) = @$pre_transform_path_sub;
	  my $new_path     = &$sub($self, $directive, $values[$i], @args);
	  if (defined $new_path and length $new_path) {
	    $values[$i] = $new_path;
	  } else {
	    $values[$i] = DEV_NULL;
	  }
	  $new_node->set_value_array(@values);
	}

	# Determine if the file or directory path needs to have the
	# ServerRoot prepended to it.  First check if the ServerRoot
	# has been set then check if the file or directory path is
	# relative for this operating system.
	my $server_root = $self->{server_root};
	if (defined $server_root and
	    length  $server_root and
	    $new_node->value_is_rel_path) {
	  $values[$i] = "$server_root/$values[$i]";
	  $new_node->set_value_array(@values);
	}

	# If the path needs to be post transformed, then do that now.
	if (my $post_transform_path_sub = $self->{post_transform_path_sub}) {
	  my ($sub, @args) = @$post_transform_path_sub;
	  my $new_path     = &$sub($self, $directive, $values[$i], @args);
	  if (defined $new_path and length $new_path) {
	    $values[$i] = $new_path;
	  } else {
	    $values[$i] = DEV_NULL;
	  }
	  $new_node->set_value_array(@values);
	}
      }
    }

    # Always set the string value using the value array.  This will
    # normalize all string values by collapsing any whitespace,
    # protect \'s, etc.
    $new_node->set_value_array(@values);

    # If this directive is ServerRoot and node is the parent node,
    # then record it now because it is used to make other relative
    # pathnames absolute.
    if ($directive eq 'serverroot' and !$self->{current_node}->mother) {
      $self->{server_root} = $values[0];
      next;
    }

    # If this directive is AccessConfig, Include or ResourceConfig,
    # then include the indicated file(s) given by the path.
    if ($directive eq 'accessconfig' or
        $directive eq 'include'      or
        $directive eq 'resourceconfig') {
      unless ($new_node->value_is_path) {
        next;
      }
      unless ($self->_handle_include_directive($file_or_dir_name,
                                               $line_number,
                                               $directive,
                                               $values[0])) {
        return;
      }
    }

    next;
  }

  unless (close($fd)) {
    $self->{errstr} = "cannot close '$file_or_dir_name' for reading: $!";
    return;
  }

  return $self;

  # At this point check if all of the context have been closed.  The
  # filename that started the context may not be the current file, so
  # get the filename from the context.
  my $root = $self->{root};
  while ($self->{current_node} != $root) {
    my $context_name     = $self->{current_node}->name;
    my $attrs            = $self->{current_node}->attributes;
    my $context_filename = $attrs->{filename};
    my $line_number      = $attrs->{line_number};
    warn "$0: '$context_filename' line $line_number context '$context_name' ",
         "was never closed.\n";
    $self->{current_node} = $self->{current_node}->mother;
  }

  $self;
}

package main;

our ($VERBOSE, $ADDWEBSERVER, $QUERYSTRING, $ADDVHOSTQUERYSTRING, $DBFILE);
our ($DBH, $NAGIOSCONFIGDIR, $GETWEBSERVERS, $DAEMON, $USENSCA, $CMD_FILE);
our ($MAXTURNAROUNDTIME, $MAXTHREADSPERHOST, $LOGGER, $CONTINUE);
our ($UPDATEWEBSERVERS, $LOCATION, $WEBAPPLICATIONSTATUSTONAGIOS);
our ($DATABASE, $USERNAME, $PASSWORD, $WEBAPPLICATION);

# The following globals are used to send web application update status to nsca
our ($NSCA, $NSCA_HOST, $NSCA_CONFIG);
$NSCA="/usr/sbin/send_nsca";
$NSCA_HOST = 'localhost';
$NSCA_CONFIG = '/etc/send_nsca.cfg';

# The max amount of time that can pass between checking vhosts in seconds
$MAXTURNAROUNDTIME = 10*60;

# This sets the maximum simultaneous web requests we can make to a server in
# an attempt to speed up the checking of server vhosts
$MAXTHREADSPERHOST = 5;

$VERBOSE = 0;
$DBFILE = dirname(abs_path($0)) .'/.'. basename($0) .'.db';
$NAGIOSCONFIGDIR = '/etc/nagios3/conf.d/';
$USENSCA = 0;
$CMD_FILE = '/var/lib/nagios3/rw/nagios.cmd';

$DATABASE = 'nagios_vhost';
$USERNAME = 'nagios_vhost';
$PASSWORD = 'nagios_vhost';
my $help;

my $result = GetOptions (
	"query-string:s"                   => \$QUERYSTRING,
	"add-web-server:s"                 => \$ADDWEBSERVER,
	"get-web-servers"                  => \$GETWEBSERVERS,
	"add-vhost-query-string:s"         => \$ADDVHOSTQUERYSTRING,
	"nagios-config-dir:s"              => \$NAGIOSCONFIGDIR,
	"update-web-servers:s"             => \$UPDATEWEBSERVERS,
	"web-application"                  => \$WEBAPPLICATION,
	"web-application-status-to-nagios" => \$WEBAPPLICATIONSTATUSTONAGIOS,
	"daemon"                           => \$DAEMON,
	"use-nsca"                         => \$USENSCA,
	"external-command-file:s"          => \$CMD_FILE,
	"nsca-host:s"                      => \$NSCA_HOST,
	"nsca-config:s"                    => \$NSCA_CONFIG,
	"database:s"                       => \$DATABASE,
	"username:s"                       => \$USERNAME,
	"password:s"                       => \$PASSWORD,
	"verbose+"                         => \$VERBOSE,
	"help"                             => \$help
);

if ($help) {
	usage();
	exit();
}

if ($DAEMON) {
	run_checks_as_daemon();
	exit();
}

initDB();
if ($ADDWEBSERVER) {
	add_new_web_server_to_db($ADDWEBSERVER);
} elsif ($GETWEBSERVERS) {
	get_web_servers();
} elsif ($ADDVHOSTQUERYSTRING) {
	die "--query-string argument required"
		if (!defined($QUERYSTRING));
	add_vhost_query_string();
} elsif (defined($UPDATEWEBSERVERS)) {
	collect_vhosts_from_webservers($UPDATEWEBSERVERS);
	generate_nagios_config_files($UPDATEWEBSERVERS);
} elsif (defined $WEBAPPLICATIONSTATUSTONAGIOS) {
	get_and_send_web_application_status_to_nagios();
} else {
	usage();
}

sub initDB{
	my ($sth, @dat, $schema_version);

	# Make sure the file exists
	# TODO: is there any reason we should be using File::Touch here?	
	#if (!-f $DBFILE) {
		#`touch $DBFILE`;
	#}

	print "Initializing application database (". $DATABASE .")\n"
		if $VERBOSE;	

	# Connect to the database
	my $dsn = "DBI:mysql:database=$DATABASE";
	$DBH = DBI->connect($dsn, $USERNAME, $PASSWORD,{ 
		RaiseError => 1,
		mysql_auto_reconnect => 1,
	}) || die "Could not connect to database: $DBI::errstr";

	# TODO: this will generate a error if the schema has not been installed yet,
	# but will not fail.
	$sth = $DBH->prepare( 
		"SELECT value FROM variables WHERE `key`='schema_version'"
	);
	eval {
		$sth->execute();
	}; if ($@ && $DBI::errstr && $DBI::errstr =~ /Table \'$DATABASE.variables\' doesn\'t exist/) {
		install();
		$sth = $DBH->prepare("INSERT INTO variables(`key`, `value`) values(?, ?)");
		$sth->execute('schema_version', 7);
	} else {
	
		$sth->execute();
		my $ref = $sth->fetchrow_hashref();
		$sth->finish();
		$schema_version = $ref->{'value'};

		if (!defined($schema_version)) {
				install();
				$sth = $DBH->prepare("INSERT INTO variables(`key`, `value`) values(?, ?)");
				$sth->execute('schema_version', 5);
		}
	}

	# Upgrade starts here
	my $st_schema = $DBH->prepare('UPDATE variables set value = ? where key = ?');
	if ($schema_version == 1) { 
		# Perform some DB upgrade operations here
		$sth = $DBH->prepare( "ALTER TABLE vhost ADD COLUMN response INT NOT NULL DEFAULT 200" );
		$sth->execute();
		
		$st_schema->execute('2', 'schema_version');		
		$schema_version = 2;
	}

	if ($schema_version == 2) { 
		# Perform some DB upgrade operations here
		$sth = $DBH->prepare(
			"CREATE TABLE redirections (
				vhost_id INTEGER,
				redirection VARCHAR,
				FOREIGN KEY(vhost_id) REFERENCES vhost(vhost_id) ON DELETE CASCADE
			)"
		);
		$sth->execute();

		$sth = $DBH->prepare(
			"CREATE TABLE variables2 (
				`key` VARCHAR(255) NOT NULL,
				`value` VARCHAR(255),
				PRIMARY KEY (`key`)
		)");
		$sth->execute();

		my $stsh = $DBH->prepare("SELECT * from variables");
		my $stih = $DBH->prepare("INSERT INTO variables2(`key`, `value`) values(?, ?)");
		$stsh->execute();
		while (my $var = $stsh->fetchrow_hashref()) {
			$stih->execute($var->{key}, $var->{value});
		}

		$sth = $DBH->prepare("DROP TABLE variables");
		$sth->execute();
			
		$sth = $DBH->prepare("ALTER TABLE variables2 RENAME TO variables");
		$sth->execute();
			
		$st_schema->execute('3', 'schema_version');		
		$schema_version = 3;
	}

	if ($schema_version == 3) {
		$sth = $DBH->prepare("SELECT * from redirections");
		$sth->execute;

		my $stvu = $DBH->prepare("UPDATE vhost SET query_string = ? where vhost_id = ?");
		while (my $rrow = $sth->fetchrow_hashref()) {
			$stvu->execute($rrow->{'redirection'}, $rrow->{'vhost_id'});
		}

		$sth = $DBH->prepare("DROP TABLE redirections");
		$sth->execute();

		$st_schema->execute('4', 'schema_version');		
		$schema_version = 4;
	}

	if ($schema_version == 4) {
		$sth = $DBH->prepare("ALTER TABLE vhost_alias add response INT");
		$sth->execute();
		$sth = $DBH->prepare("ALTER TABLE vhost_alias add column query_string VARCHAR(255)");
		$sth->execute();
		$st_schema->execute('5', 'schema_version');		
		$schema_version = 5;
	}

	if ($schema_version == 5) {
		$sth = $DBH->prepare(
			"CREATE TABLE vhost_url (
				vhost_id INTEGER,
				name VARCHAR(255),
				path VARCHAR(255),
				response INT NOT NULL DEFAULT 200,
				query_string VARCHAR(255),
				FOREIGN KEY(vhost_id) REFERENCES vhost(vhost_id) ON DELETE CASCADE
		)");
		$sth->execute();
		$st_schema->execute('6', 'schema_version');		
		$schema_version = 6;
	}

	if ($schema_version == 6) {
		$sth = $DBH->prepare(
			"CREATE TABLE vhost_application (
				vhost_id INTEGER,
				type VARCHAR(255),
				path VARCHAR(255),
				FOREIGN KEY(vhost_id) REFERENCES vhost(vhost_id) ON DELETE CASCADE
		)");
		$sth->execute();
		$st_schema->execute('7', 'schema_version');		
		$schema_version = 7;
	}
}

sub install {
	my $sth;
	$sth = $DBH->prepare(
		"CREATE TABLE variables (
			`key` VARCHAR(255) NOT NULL,
			`value` VARCHAR(255),
			PRIMARY KEY (`key`)
	)");
	$sth->execute();
	$sth->finish();

	# we keep a seperate column for the nagios_host_name because this may
	# be different then what the host this script is running from uses to
	# actually ssh to / web client to
	$sth = $DBH->prepare(
		"CREATE TABLE host (
			host_id INTEGER PRIMARY KEY AUTO_INCREMENT,
			last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			name VARCHAR(255) NOT NULL,
			`nagios_host_name` VARCHAR(255),
			UNIQUE(name)
	)");
	$sth->execute();
	$sth->finish();

	# Sometimes webservers have multiple ips.  In this case checking all vhosts
	# against the ip of the webserver returned from DNS is insufficient.  We also
	# need the ip address that is included in the
	# the VirtualHost directive if it exists.  If not we can use the ip address
	# of the webserver.  
	$sth = $DBH->prepare(
		"CREATE TABLE vhost (
			host_id INTEGER,
			vhost_id INTEGER PRIMARY KEY AUTO_INCREMENT,
			last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			name VARCHAR(255),
			ip VARCHAR(15),
			port INT NOT NULL DEFAULT 80,
			response INT NOT NULL DEFAULT 200,
			query_string VARCHAR(255),
			FOREIGN KEY(host_id) REFERENCES host(host_id) ON DELETE CASCADE
	)");
	$sth->execute();
	$sth->finish();

	$sth = $DBH->prepare(
		"CREATE TABLE vhost_alias (
			vhost_id INTEGER,
			last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			name VARCHAR(255),
			response INT DEFAULT NULL,
			query_string VARCHAR(255) DEFAULT NULL,
			UNIQUE KEY `vhost_alias_unique_vhost_id_name_index` (`vhost_id`,`name`),
			FOREIGN KEY(vhost_id) REFERENCES vhost(vhost_id) ON DELETE CASCADE
	)");
	$sth->execute();
	$sth->finish();

	$sth = $DBH->prepare(
		"CREATE TABLE vhost_url (
			vhost_id INTEGER,
			name VARCHAR(255),
			path VARCHAR(255),
			response INT DEFAULT NULL,
			query_string VARCHAR(255) DEFAULT NULL,
			FOREIGN KEY(vhost_id) REFERENCES vhost(vhost_id) ON DELETE CASCADE
	)");
	$sth->execute();
	$sth->finish();

	$sth = $DBH->prepare(
		"CREATE TABLE vhost_application (
			vhost_id INTEGER,
			type VARCHAR(255),
			path VARCHAR(255),
			FOREIGN KEY(vhost_id) REFERENCES vhost(vhost_id) ON DELETE CASCADE
	)");
	$sth->execute();
	$sth->finish();
}

sub add_new_web_server_to_db{
	my ($host) = @_;
	my $sth = $DBH->prepare('INSERT INTO host(name, nagios_host_name) values(?, ?)') 
		|| die "$DBI::errstr";;

	$host =~ /^([^.]+)\./;
	$sth->execute($host, $1);
	print "inserted $host into the host table\n" 
		if $VERBOSE;
}

sub get_web_servers{
	my $sth = $DBH->prepare('SELECT host_id,name from host')
		|| die "$DBI::errstr";
	my $stv = $DBH->prepare('SELECT vhost_id,name,port,query_string from vhost where host_id=? order by name')
		|| die "$DBI::errstr";
	my $sta = $DBH->prepare('SELECT name from vhost_alias where vhost_id=? order by name') 
		|| die "$DBI::errstr";

	$sth->execute();

	while (my $host = $sth->fetchrow_hashref()) {
		print $host->{name} ."\n";
		$stv->execute($host->{host_id});
		while (my $vhost = $stv->fetchrow_hashref()) {
			$sta->execute($vhost->{vhost_id});
			my @aliases;
			while (my $alias = $sta->fetchrow_hashref()) {
				push @aliases, $alias->{name};
			}

			my $vhost_str = "\t". $vhost->{name}. ':'. $vhost->{port}; 

			if ($#aliases >= 0) {
				$vhost_str .= ": ". join(', ', @aliases);
			}

			if (defined($vhost->{query_string})) {
				$vhost_str .= ': "'. $vhost->{query_string} .'"';
			}
			print $vhost_str ."\n";
		}
	}
}

# Log into all of the configured servers
# Get a list of all vhosts
# Disable any vhosts we had on record
# Add any new vhosts and associated alieas
# Update any new aliases
sub collect_vhosts_from_webservers {
	my ($hosts) = @_;
	my $sth = $DBH->prepare('SELECT host_id,name from host')
		|| die "$DBI::errstr";;
	my $stv = $DBH->prepare('
		SELECT * from vhost 
		LEFT JOIN vhost_application on (vhost.vhost_id = vhost_application.vhost_id)
		WHERE host_id=?
	') || die "$DBI::errstr";;
	my $stvd = $DBH->prepare('DELETE from vhost where vhost_id=?')
		|| die "$DBI::errstr";;
	my $stvu = $DBH->prepare('UPDATE vhost set ip = ? where vhost_id = ?')
		|| die "$DBI::errstr";;
	my $stva = $DBH->prepare('SELECT * from vhost_alias where vhost_id=?')
		|| die "$DBI::errstr";;
	my $stvad = $DBH->prepare('DELETE from vhost_alias where vhost_id=? and name=?')
		|| die "$DBI::errstr";;
	my $stud = $DBH->prepare('DELETE from vhost_url where vhost_id=?')
		|| die "$DBI::errstr";;
	my $stvai = $DBH->prepare('INSERT INTO vhost_alias(vhost_id, name) values(?, ?)')
		|| die "$DBI::errstr";;
	my $stvi = $DBH->prepare('INSERT INTO vhost(host_id, name, port, ip) values(?, ?, ?, ?)')
		|| die "$DBI::errstr";;
	my $stvui = $DBH->prepare('INSERT INTO vhost_url(vhost_id, name, path, response, query_string) values(?, ?, ?, ?, ?)')
		|| die "$DBI::errstr";;
	my $stvapd = $DBH->prepare('DELETE from vhost_application where vhost_id=?')
		|| die "$DBI::errstr";;
	my $stvapi = $DBH->prepare('INSERT INTO vhost_application(vhost_id, type, path) values(?, ?, ?)')
		|| die "$DBI::errstr";;
	my $stvur = $DBH->prepare('UPDATE vhost set response = ?, query_string = ? where name = ?')
		|| die "$DBI::errstr";;
	my $stvuvar = $DBH->prepare('UPDATE vhost_alias set response = ?, query_string = ? where name = ?')
		|| die "$DBI::errstr";;

	my $get_config_file_cmd = "/bin/cat ";

	# If we are passed in a host list, then process it
	if ($hosts ne '') {
		my $query = 'SELECT host_id,name from host where ';
		my $first = 1;
		my @hosts;
		foreach (split /,/, $hosts) {
			push @hosts, $_;
			if (!$first) { $query .= ' or '; }
			else { $first = 0; }

			$query .= 'name = ?';
		}

		$sth = $DBH->prepare($query);
		$sth->execute(@hosts);

	} else {
		$sth->execute();
	}

	while (my $host = $sth->fetchrow_hashref()) {
		my %vhosts;
		print "Getting vhost information from ". $host->{name} ."...\n" if $VERBOSE;

		# Get the ip of the host from DNS
		my $res = Net::DNS::Resolver->new;
		my $query = $res->search($host->{name});
		my $ip;
		if ($query) {
			foreach my $rr ($query->answer) {
					next unless $rr->type eq "A";
					$ip = $rr->address;
			}
		} else {
			# TODO: this should be a log message and should not die
			die "query failed(". $host->{name} ."): ". $res->errorstring;
		}

		my $get_vhosts_cmd = "apachectl -t -D DUMP_VHOSTS";
		print "Running `$get_vhosts_cmd`\n" if $VERBOSE;	
		my $vhosts = sshopen3($host->{name}, *WRITER, *READER, *ERROR, $get_vhosts_cmd);

		# Some hosts this is not going to run unless we specify the path
		if (<ERROR> =~ /command not found/) {
			$get_vhosts_cmd = '/usr/sbin/'. $get_vhosts_cmd;
			print "Running `$get_vhosts_cmd`\n" if $VERBOSE;	
			$vhosts = sshopen2($host->{name}, *READER, *WRITER, $get_vhosts_cmd);
		}

		# Some hosts this is not going to run well without elevated privileges
		if (<READER> =~ /Action.*failed/) {
			$get_vhosts_cmd = 'sudo '. $get_vhosts_cmd;
			print "Running `$get_vhosts_cmd`\n" if $VERBOSE;	
			$vhosts = sshopen2($host->{name}, *READER, *WRITER, $get_vhosts_cmd);
		}

		while (<READER>) {
			my $vhost_line = $_;
			next if (
				$vhost_line !~ /port (\d+) namevhost ([^\s]+) \(([^:]+):\d+\)/
				&&
				$vhost_line !~ /(?:[^:]+):(\d+) \s+ ([^\s]+) \(([^:]+):\d+\)/
			);
			my $port = $1;
			my $vhost = $2;	
			my $config = $3;

			# Get all of the aliases from the config file
			my $cmd = $get_config_file_cmd . $config ."|grep -vi include";
			print "\tGetting the config file for $vhost:$port ($config) ...\n" if $VERBOSE;
			sshopen2($host->{name}, *READER2, *WRITER, $cmd) ||
				die "ssh: $!";

			my $acp = Apache::ConfigParserWithFileHandle->new;
			my $rc = $acp->parse_file(*READER2);

			# TODO: some better error handling here may be in order
			if (!$rc) {
				exit;
			}

			# The ServerName directive may appear anywhere within the definition of 
			# a server. However, each appearance overrides the previous appearance 
			# (within that server).  Note, this is not a required directive, some
			# vhost configs may still not include it!
			my @aliases;

			foreach my $apache_vhost ($acp->find_down_directive_names('virtualhost')) {
				my @sn = $acp->find_down_directive_names($apache_vhost, 'servername');
				my $sn = $sn[0];
				my $server_name  = $sn->{value};
				next if ($server_name ne $vhost);

				# Some vhost configs do not have any server names
				#next if ! ($sn && $sn->{value});
				my $virtual_host = $apache_vhost->{value};
				next if ($virtual_host !~ /([^:]+):$port/);

				my @server_aliases  = $acp->find_down_directive_names($apache_vhost, 'serveralias');
				my @document_roots  = $acp->find_down_directive_names($apache_vhost, 'documentroot');
				my $document_root   = $document_roots[0]?$document_roots[0]->value:'';
				my @ssl_engine      = $acp->find_down_directive_names($apache_vhost, 'sslengine');
				my $ssl_engine      = $ssl_engine[0]?$ssl_engine[0]->value:'';


				# For EE jails vhosts will be configured to proxy ssl connections 
				# through NGINX.  We will see the ssl based vhosts configured to
				# listen on port 444.  The following section of code will attempt
				# to compensate for this
				$port = 443 if ($port == 444 && $ssl_engine =~ /on/i);
				$vhosts{$vhost}{$port}{config} = $config;

				# This code should prevent vhosts from ending up without an ip
				my $vhost_ip = $1;
				$vhosts{$vhost}{$port}{ip} = $ip;
				my $regexp = create_iprange_regexp(
              qw( 10.0.0.0/8 87.134.66.128 87.134.87.0/24 145.97.0.0/16 )
           );
				if (
					$vhost_ip && 
					($vhost_ip ne '*') && 
					($vhost_ip !~ /\s/) &&

					# EE's vhosts are actually on an internal ip proxied from its public ip
					!match_ip($vhost_ip, $regexp)
				) {
					$vhosts{$vhost}{$port}{ip} = $vhost_ip;
				}

				$vhosts{$vhost}{$port}{port} = $port;
				$vhosts{$vhost}{$port}{name} = $vhost;
				# Record where the documentroot is
				$vhosts{$vhost}{$port}{documentroot} = $document_root;

				# Log back into the server and attempt to determine the application type
				$vhosts{$vhost}{$port}{application} = 
          check_vhost_application_type($host->{name}, $vhosts{$vhost}{$port}{documentroot})
					if ($WEBAPPLICATION);

				foreach my $sa (@server_aliases) {
					my $sav = $sa->value;
					foreach my $alias (split(/\s+/, $sav)) {
						$alias =~ s/^\*/meow/;
						push(@aliases, $alias);
					}
				}

			}

			print "\tFound the aliases for $vhost:$port: ". join(', ', @aliases) ."...\n" if $VERBOSE;
			$vhosts{$vhost}{$port}{aliases} = \@aliases;
		}

		# We can't just delete the hosts because users may have added 
		# query_strings for them that need to be persistent.  

		# Disable all vhosts that exist in the database that were not returned
		$stv->execute($host->{host_id});
		while (my $vhost = $stv->fetchrow_hashref()) {

			if (!defined($vhosts{$vhost->{name}}{$vhost->{port}})) {
				print "\t". $vhost->{name} .":". $vhost->{port} ." is no longer hosted on ". $host->{name}
					.". Removing it from the DB...\n" if $VERBOSE;
				$stvd->execute($vhost->{vhost_id});
				next;
			}

			# If ip has changed then update it
			if ($vhost->{ip} && $vhosts{$vhost->{name}}{$vhost->{port}}{ip} ne $vhost->{ip}) {
				$stvu->execute($vhosts{$vhost->{name}}{$vhost->{port}}{ip}, $vhost->{vhost_id});
			}

			# Delete vhost_alias' associated with the vhost if they are no longer defined
			$stva->execute($vhost->{vhost_id});
			while (my $vhost_alias = $stva->fetchrow_hashref()) {
				$stvad->execute($vhost->{vhost_id}, $vhost_alias->{name})
					if(!grep($vhost_alias->{name}, @{$vhosts{$vhost->{name}}{$vhost->{port}}{aliases}}));
			}

			# We just remove the application types we found and then re-add them
			print "\tRemoving vhost_application rows for ". $vhost->{name} .":". $vhost->{port} ."...\n" 
        if ($VERBOSE && $WEBAPPLICATION);
			$stvapd->execute($vhost->{vhost_id})
        if ($VERBOSE && $WEBAPPLICATION);

			print "\tInserting ". $vhosts{$vhost->{name}}{$vhost->{port}}{application} .
				" as application for ". $vhost->{name} .":". $vhost->{port} ."...\n" 
				if $VERBOSE && $vhosts{$vhost->{name}}{$vhost->{port}}{application} && $WEBAPPLICATION;

			if ($vhosts{$vhost->{name}}{$vhost->{port}}{application}) {
				$stvapi->execute(
					$vhost->{vhost_id}, 
					$vhosts{$vhost->{name}}{$vhost->{port}}{application}, 
					$vhosts{$vhost->{name}}{$vhost->{port}}{documentroot}
				);
			}

			delete($vhosts{$vhost->{name}}{$vhost->{port}});
		}

		# Insert all new vhosts
		foreach (keys %vhosts) {
			my $vhost = $_;
			foreach (keys %{$vhosts{$vhost}}) {
				my $port = $_;
				print "Adding new vhost: $vhost:$port (". $host->{host_id} .")...\n" if $VERBOSE;
				$stvi->execute($host->{host_id}, $vhost, $port, $vhosts{$vhost}{$port}{ip});
				my $rowid = $stvi->{mysql_insertid};

				foreach (@{$vhosts{$vhost}{$port}{aliases}}) {
					print "Adding $_ as alias for $vhost:$port...\n" if $VERBOSE;
					# There is a UNIQUE key constraint on vhost_id and name, if we
					# attempt to add a new row that already exists silently ignore
					eval { $stvai->execute($rowid, $_); };
				}
				
				print "\tInserting ". $vhosts{$vhost}{$port}{application} ." as application for ". $vhost .":". $port ."...\n" 
					if $VERBOSE && $vhosts{$vhost}{$port}{application};	
				$stvapi->execute($rowid, $vhosts{$vhost}{$port}{application}, $vhosts{$vhost}{$port}{documentroot})
					if $vhosts{$vhost}{$port}{application};	

			}
		}


	}
	
}

sub check_vhost_application_type {
	my ($host, $path) = @_;
	print "\tcheck_vhost_application_type($host, $path)\n" if $VERBOSE>1;

	my $test_for_drupal_command = "grep Drupal $path/CHANGELOG.txt | wc -l ";
	my $test_for_wordpress_command = "grep WordPress $path/license.txt | wc -l ";

	print "\tRunning `$test_for_drupal_command`\n" if $VERBOSE >1;	
	sshopen2($host, *READER3, *WRITER3, $test_for_drupal_command);
	my $line;
	$line = <READER3>;
	close READER3;
	close WRITER3;
	return 'Drupal' if $line && ($line > 0);

	print "\tRunning `$test_for_wordpress_command`\n" if $VERBOSE >1;	
	sshopen2($host, *READER4, *WRITER4, $test_for_wordpress_command);
	$line = <READER4>;
	close READER4;
	close WRITER4;
	return 'WordPress' if $line && ($line > 0);
}

sub generate_check_vhost_config_files {
	my $sth = $DBH->prepare("SELECT host_id,name from host")
		|| die "$DBI::errstr";

	my $stv = $DBH->prepare(
		"SELECT vhost.vhost_id,name,port,query_string FROM vhost WHERE host_id = ?")
		|| die "$DBI::errstr";

	my $stva = $DBH->prepare(
		"SELECT name FROM vhost_alias WHERE vhost_id = ?")
		|| die "$DBI::errstr";

	#	"SELECT vhost.name,ivhost_alias.name,port,query_string FROM vhost ".
	#		"LEFT JOIN vhost_alias ON (vhost.rowid = vhost_alias.vhost_id) ".
	#		"WHERE vhost.host_id = ?"

	# Create a new config file for each host
	# The format of the config file is our modified version of the check_vhosts
	# script: http://exchange.nagios.org/directory/Plugins/Web-Servers/check_vhosts/details
	$sth->execute();
	while (my $host = $sth->fetchrow_hashref()) {
		# TODO: do this
		print "Creating vhost config file for ". $host->{name} ."(". $NAGIOSCONFIGDIR . $host->{name} .".txt...\n" 
			if $VERBOSE;
		open (HOSTFILE, '+>', $NAGIOSCONFIGDIR . $host->{name} .'.txt')
			|| die('Could not open the vhost config file ('. $NAGIOSCONFIGDIR . $host->{name} .'.txt' .'): '. $?);
		$stv->execute($host->{host_id});
		while (my $vhost = $stv->fetchrow_hashref()) {
			print HOSTFILE $vhost->{name} ." ".$vhost->{port} ." ". 
				(defined($vhost->{query_string})?$vhost->{query_string}:'') ."\n";
			$stva->execute($vhost->{vhost_id});
			while (my $vahost = $stva->fetchrow_hashref()) {
				print HOSTFILE $vahost->{name} ." ".$vhost->{port} ." ". 
					(defined($vhost->{query_string})?$vhost->{query_string}:'') ."\n";
			}
		}
		close HOSTFILE;
	}
}

# Make sure there is no error in the config and then reload the server
sub reload_nagios {
	print "reload_nagios()\n";
}

# TODO: do we need to be able to add different query_strings for different 
# vhosts based by port?
sub add_vhost_query_string {
	my $sth = $DBH->prepare('SELECT vhost_id FROM vhost WHERE name = ?')
		|| die "$DBI::errstr";;
	$sth->execute($ADDVHOSTQUERYSTRING);
	my $vhost = $sth->fetchrow_hashref();
	die 'Can not add a query string for a vhost that has not been added yet. '.
		$ADDVHOSTQUERYSTRING .' does not exist in the database'
		if (!$vhost->{vhost_id});

	# TODO: we should prolly sanitize this data we are inserting
	$sth = $DBH->prepare('UPDATE vhost set query_string = ? WHERE name = ?')
		|| die "$DBI::errstr";;
	$sth->execute($QUERYSTRING, $ADDVHOSTQUERYSTRING);

	print "Added query string:\"$QUERYSTRING\" for $ADDVHOSTQUERYSTRING...\n"
		if $VERBOSE;
}

sub generate_nagios_config_files {
	my ($hosts) = @_;
	my $sth = $DBH->prepare("SELECT host_id,name from host")
		|| die "$DBI::errstr";

	my $stv = $DBH->prepare(
		"SELECT vhost.vhost_id,name,port,query_string FROM vhost WHERE host_id = ?")
		|| die "$DBI::errstr";

	my $stva = $DBH->prepare(
		"SELECT name FROM vhost_alias WHERE vhost_id = ?")
		|| die "$DBI::errstr";

	my $stvu = $DBH->prepare(
		"SELECT name,path FROM vhost_url WHERE vhost_id = ?")
		|| die "$DBI::errstr";

	my $stvas = $DBH->prepare(
		"SELECT type,path FROM vhost_application WHERE vhost_id = ?")
		|| die "$DBI::errstr";

	# Create a new config file for each host
	# The format of the config file is our modified version of the check_vhosts
	# script: http://exchange.nagios.org/directory/Plugins/Web-Servers/check_vhosts/details

	# If we are passed in a host list, then process it
	if ($hosts ne '') {
		my $query = 'SELECT host_id,name from host where ';
		my $first = 1;
		my @hosts;
		foreach (split /,/, $hosts) {
			push @hosts, $_;
			if (!$first) { $query .= ' or '; }
			else { $first = 0; }

			$query .= 'name = ?';
		}

		$sth = $DBH->prepare($query);
		$sth->execute(@hosts);

	} else {
		$sth->execute();
	}

	while (my $host = $sth->fetchrow_hashref()) {
		# TODO: do this
		$host->{name} =~ /^([^\.]+)/;
		my $short_hostname = $1;
		print "Creating vhost config file for ". $host->{name} ."(". $NAGIOSCONFIGDIR . $host->{name} ."_vhosts.cfg...\n" 
			if $VERBOSE;
		open (HOSTFILE, '>', $NAGIOSCONFIGDIR . $host->{name} .'_vhosts.cfg')
			|| die('Could not open the vhost config file ('. $NAGIOSCONFIGDIR . $host->{name} .'_vhosts.cfg' .'): '. $?);
		$stv->execute($host->{host_id});
		my ($cluster, $wp_cluster, $drupal_cluster);
		while (my $vhost = $stv->fetchrow_hashref()) {

			# TODO: these definitions should not referrnce of nagios config node 
			# types that are not defined here.  We cobbled in support for vhosts,
			# web_application_updates, drupal_updates, wordpress_updates
			print HOSTFILE "define service {\n".
				"\tuse generic-service-passive-no-notification-no-perfdata\n".
				"\tservice_description ". $vhost->{name} .':'. $vhost->{port} .' on '. $host->{name} ."\n".
				"\tservicegroups ". $host->{name} ."_vhosts, vhosts\n".
				"\thost_name $short_hostname\n}\n\n";

			$cluster .= '$SERVICESTATEID:'. $short_hostname .':'. 
				$vhost->{name} .':'.  $vhost->{port} .' on '. $host->{name} .'$,';

			print HOSTFILE "define servicedependency {\n".
				"\thost_name $short_hostname\n".
				"\tservice_description HTTP\n".
				"\tdependent_host_name $short_hostname\n".
				"\tdependent_service_description ". $vhost->{name} .':'. $vhost->{port} .' on '. $host->{name} ."\n".
				"\texecution_failure_criteria n\n".
				"\tnotification_failure_criteria w,u,c,p\n}\n\n";

			$stva->execute($vhost->{vhost_id});
			while (my $vahost = $stva->fetchrow_hashref()) {
				print HOSTFILE "define service {\n".
					"\tuse generic-service-passive-no-notification-no-perfdata\n".
					"\tservice_description ". $vahost->{name} .':'. $vhost->{port} .' on '. $host->{name} ."\n".
					"\tservicegroups ". $host->{name} ."_aliases, vhosts\n".
					"\thost_name $short_hostname\n}\n\n";

				$cluster .= '$SERVICESTATEID:'. $short_hostname .':'. 
					$vahost->{name} .':'. 
					$vhost->{port} .' on '. $host->{name} .'$,';

				print HOSTFILE "define servicedependency {\n".
					"\thost_name $short_hostname\n".
					"\tservice_description HTTP\n".
					"\tdependent_host_name $short_hostname\n".
					"\tdependent_service_description ". $vahost->{name} .':'. $vhost->{port} .' on '. $host->{name} ."\n".
					"\texecution_failure_criteria n\n".
					"\tnotification_failure_criteria w,u,c,p\n}\n\n";
			}

			# Generate the configs for the vhost urls
			# Its possible there is no path
			$stvu->execute($vhost->{vhost_id});
			while (my $vuhost = $stvu->fetchrow_hashref()) {
				my $path = $vuhost->{path}?$vuhost->{path}:'';

				print HOSTFILE "define service {\n".
					"\tuse generic-service-passive-no-notification-no-perfdata\n".
					"\tservice_description ". $vuhost->{name} .':'. $vhost->{port} . $path .' on '. $host->{name} ."\n".
					"\tservicegroups ". $host->{name} ."_urls, vhosts\n".
					"\thost_name $short_hostname\n}\n\n";

				$cluster .= '$SERVICESTATEID:'. $short_hostname .':'. 
					$vuhost->{name} .':'. $vhost->{port} . $path .' on '. 
					$host->{name} .'$,';

				print HOSTFILE "define servicedependency {\n".
					"\thost_name $short_hostname\n".
					"\tservice_description HTTP\n".
					"\tdependent_host_name $short_hostname\n".
					"\tdependent_service_description ". $vuhost->{name} .':'. $vhost->{port} . $path .' on '. $host->{name} ."\n".
					"\texecution_failure_criteria n\n".
					"\tnotification_failure_criteria w,u,c,p\n}\n\n";
			}

			# Create Nagios config entries for the web applications
			$stvas->execute($vhost->{vhost_id});
			while (my $vhostapp = $stvas->fetchrow_hashref()) {
				print HOSTFILE "define service {\n".
					"\tuse generic-service-passive-no-notification-onceaday\n".
					"\tservice_description ". $vhost->{name} .':'. $vhost->{port} .' on '. 
						$host->{name} ." ". $vhostapp->{type} ." Updates\n".
					"\tservicegroups ". $host->{name} ."_". lc($vhostapp->{type}) .
					"_updates, web_application_updates, ".
					lc($vhostapp->{type}) ."_updates\n".
					"\thost_name $short_hostname\n}\n\n";

				if ($vhostapp->{type} =~ /Drupal/) {
					$drupal_cluster .= ',' if $drupal_cluster;
					$drupal_cluster .= '$SERVICESTATEID:'. $short_hostname .':'. 
						$vhost->{name} .':'. $vhost->{port} .' on '. 
							$host->{name} ." Drupal Updates\$";
				} elsif ($vhostapp->{type} =~ /WordPress/) {
          $wp_cluster .= ',' if $wp_cluster;
          $wp_cluster .= '$SERVICESTATEID:'. $short_hostname .':'. 
            $vhost->{name} .':'. $vhost->{port} .' on '. 
              $host->{name} ." WordPress Updates\$";
        }

				print HOSTFILE "define servicedependency {\n".
					"\thost_name $short_hostname\n".
					"\tservice_description ". $vhostapp->{type} ." Updates\n".
					"\tdependent_host_name $short_hostname\n".
					"\tdependent_service_description ". $vhost->{name} .':'. $vhost->{port} .
						' on '. $host->{name} ." ". $vhostapp->{type} ." Updates\n".
					"\texecution_failure_criteria n\n".
					"\tnotification_failure_criteria w,u,c,p\n}\n\n";
			}
		}

#		print HOSTFILE "define servicedependency {\n".
#			"\thost_name $short_hostname\n".
#			"\tservice_description HTTP\n".
#			"\tdependent_host_name $short_hostname\n".
#			"\tdependent_service_description ^.* on huang.radicaldesigns.org\$\n".
#			"\texecution_failure_criteria n\n".
#			"\tnotification_failure_criteria w,u,c,p\n}\n\n";

		print HOSTFILE "define servicegroup {\n".
			"\tservicegroup_name ". $host->{name} ."_vhosts\n}\n\n";
		print HOSTFILE "define servicegroup {\n".
			"\tservicegroup_name ". $host->{name} ."_aliases\n}\n\n";
		print HOSTFILE "define servicegroup {\n".
			"\tservicegroup_name ". $host->{name} ."_urls\n}\n\n";
		print HOSTFILE "define servicegroup {\n".
			"\tservicegroup_name ". $host->{name} ."_drupal_updates\n}\n\n";
		print HOSTFILE "define servicegroup {\n".
			"\tservicegroup_name ". $host->{name} ."_wordpress_updates\n}\n\n";

		$cluster =~ s/,$//;
		print HOSTFILE "define service{\n".
			"\tuse generic-service\n".
			"\tservice_description HTTP Vhosts\n".
			"\thost_name $short_hostname\n".
			"\tcheck_command check_service_cluster!\"HTTP Vhosts\"!0!1!$cluster\n}\n\n";

		print HOSTFILE "define service{\n".
			"\tuse generic-service\n".
			"\tservice_description Drupal Updates\n".
			"\thost_name $short_hostname\n".
			"\tcheck_command check_service_cluster!\"Drupal Updates\"!0!1!$drupal_cluster\n}\n\n"
			if $drupal_cluster;

		print HOSTFILE "define service{\n".
			"\tuse generic-service\n".
			"\tservice_description WordPress Updates\n".
			"\thost_name $short_hostname\n".
			"\tcheck_command check_service_cluster!\"Wordpress Updates\"!0!1!$wp_cluster\n}\n\n"
			if $wp_cluster;

		close HOSTFILE;
	}
}

# TODO: wrap the remaining db execute statements in eval blocks
sub run_checks_as_daemon {
	use Log::Log4perl qw(get_logger :levels);
	use Proc::Daemon;
	use WWW::Mechanize;
	use Log::Dispatch;
	use LWP::ConnCache;

	my $appender = Log::Log4perl::Appender->new(
		"Log::Dispatch::Syslog",
		#"Log::Log4perl::Appender::Screen",
		'ident' => basename($0),
		'facility' => 'daemon',
	);

	$LOGGER = get_logger("Daemon");
	$LOGGER->add_appender($appender);
	$LOGGER->level($INFO);
	#$LOGGER->level($WARN);
  #$LOGGER->level($DEBUG);
	#$LOGGER->debug('Logger initialized');

	my $servers;
	my $TERMD = 0;
	$SIG{TERM} = sub { 
		my @kids = keys %{$servers};
		$TERMD = 1;
		kill 9, @kids;
	};
	
	# With this handler does this mean that each child will inherit this? Yes,
	# but each child has its own process so it does not get printed by each 
	# process only the one you send the signal to
	$SIG{USR1} = sub { print_statistics(); };

	Proc::Daemon::Init;
	initDB();
	$LOGGER->debug('Application daemonized');

	# Loop across all of the vhosts and alias' in the database and submit 
	# Passive checks for them
	my $sth = $DBH->prepare("SELECT host_id,name from host") 
          || die "$DBI::errstr";

	eval {
		$sth->execute();
	};
	if ($@) {
		$LOGGER->fatal($@);
		die $@;
	}

	while (my $host = $sth->fetchrow_hashref()) {
		my $pid = fork_server($host->{host_id}, $host->{name});
		$servers->{$pid}->{host_id} = $host->{host_id};
		$servers->{$pid}->{name} = $host->{name};
	}

	# Don't abandon your children
	my $kid;
	do {
		$kid = wait;	
		$LOGGER->debug('Process ('. $kid .') exited');
		if (!$TERMD) {
			my $pid = fork_server($servers->{$kid}->{host_id}, $servers->{$kid}->{name});
			$servers->{$pid}->{host_id} = $servers->{$kid}->{host_id};
			$servers->{$pid}->{name} = $servers->{$kid}->{name};
		}
		delete $servers->{$kid};
	} while $kid > 0;
	exit;
}

sub fork_server {
		my ($hostid, $hostname) = @_;
		my $pid = fork();
		if ($pid) {
			$LOGGER->debug('New process ('. $pid .') started to handle '. $hostname .' vhosts');
			return $pid;
		} else {
			$0 = $0 ." [". $hostname ."]";
			process_server_vhosts($hostid, $hostname);
			exit 0;
		}
}

# We actually want to stay on the same server so we only chnage the HOST
# and the path.
# If the handler returns an HTTP::Request object we'll start over with processing this request instead.
sub response_redirect {
	my($response, $ua, $h) = @_;

	my $url;
	$LOGGER->warn("response_redirect location header: ". $response->header('Location'));
	$LOGGER->warn("response_redirect LOCATION: $LOCATION");
	
	if ($response->header('Location')) {

		# This is an ugly fix, but to help keep us from ending up in the 
		# redirection loop then we need to check against a possible 
		# redirection location set in the check_host method.
    $LOGGER->info("response_redirect() redirectissue: ". $response->header('Location') ." <==> $LOCATION") if ($LOCATION =~ /radicaldesigns.org/);
		if ($response->header('Location') eq $LOCATION) {
			$LOCATION = 'matched';
			return;
		}

		$response->request()->as_string() =~ /GET\s+(http[^:]*):\/\/([^\/\s]+)/;
		my $http = $1;
		my $ip = $2;
		$LOGGER->debug("response_redirect() recived Location header: ". $response->header('Location'));
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

# This method is responsible for timing and possibly invoking new threads to decrease the
# turn around time on vhost checks up to a limit.
sub process_server_vhosts {
	my ($host_id, $hostname) = @_;
	use Time::HiRes qw(usleep);
	my $sleep = 0;
	my $threads = 1;
	my $total_time = 0;
	my %children;
	$SIG{USR1} = sub { print_statistics($host_id, $total_time, $sleep, $threads); };

	# Set up the query
	my $stv = $DBH->prepare(
		"SELECT vhost.vhost_id,name,port,ip,query_string,response FROM vhost ".
		"WHERE host_id = ?")
		|| die "$DBI::errstr";

	my $stva = $DBH->prepare(
		"SELECT name,query_string,response FROM vhost_alias WHERE vhost_id = ?")
		|| die "$DBI::errstr";

	my $stu = $DBH->prepare(
		"SELECT name,path,query_string,response ".
		"FROM vhost_url ".
		"WHERE vhost_id = ?")
		|| die "$DBI::errstr";

	$LOGGER->debug("process_server_vhosts($host_id, $hostname)\n");

	while (1) {
		my $start = time();
		# start processing vhosts and aliases
		$stv->execute($host_id);
		my $num_vhosts = 0;	

		while (my $vhost = $stv->fetchrow_hashref()) {
			$LOGGER->debug('process_server_vhosts(): Processing vhost '. $vhost->{name} .' for '. $hostname);
			$num_vhosts++;
			if ($sleep) {
				$LOGGER->debug("Sleeping for $sleep ms");
				usleep($sleep);
			} 

			if ($threads > 1) {
				$LOGGER->debug('Running in threaded mode with '. $threads .' processes for the '. $hostname .' loop');
				if (scalar(keys %children) == $threads) {
					# wait for a kid to finish
					$LOGGER->debug('Already have '. scalar(keys %children) .' processes for this loop, waiting for one to return');
					my $kid = wait;
					$LOGGER->debug($kid .' returned');
					delete $children{$kid};
				} 

				# birth a new child
				my $pid = fork();
				if ($pid) {
					$LOGGER->debug('Forked a new process ('. $pid .')');
					$children{$pid} = 1;
				} else {
					check_host($vhost->{name}, $vhost->{ip}, $vhost->{port}, 
						$vhost->{query_string}, $hostname, $vhost->{response});
					exit 0;
				}
			} else {
				check_host($vhost->{name}, $vhost->{ip}, $vhost->{port}, 
					$vhost->{query_string}, $hostname, $vhost->{response});
			}

			$stva->execute($vhost->{vhost_id});
			while (my $vhost_alias = $stva->fetchrow_hashref()) {
				$LOGGER->debug('process_server_vhosts(): Processing vhost alias '. $vhost_alias->{name} .' for '. $hostname);
				$num_vhosts++;
				if ($sleep) {
					usleep($sleep);
				} 

				my $query_string = $vhost_alias->{query_string} ? $vhost_alias->{query_string} : $vhost->{query_string};
				my $response = $vhost_alias->{response} ? $vhost_alias->{response} : $vhost->{response};
				if ($threads>1) {
					if (scalar(keys %children) == $threads) {
						$LOGGER->debug('Already have '. scalar(keys %children) .' processes for this loop, waiting for one to return');
						# wait for a kid to finish
						my $kid = wait;
						$LOGGER->debug($kid .' returned');
						delete $children{$kid};
					} 

					# birth a new child
					my $pid = fork();
					if ($pid) {
						$LOGGER->debug('Forked a new process ('. $pid .')');
						$children{$pid} = 1;
					} else {
						check_host($vhost_alias->{name}, $vhost->{ip}, $vhost->{port}, 
							$query_string, $hostname, $response);
						exit 0;
					}
				} else {
					check_host($vhost_alias->{name}, $vhost->{ip}, $vhost->{port}, 
						$query_string, $hostname, $response);
				}
			} # Loop all vhost aliases

			$stu->execute($vhost->{vhost_id});
			while (my $vhost_url = $stu->fetchrow_hashref()) {
				$LOGGER->debug('process_server_vhosts(): Processing vhost url '. $vhost_url->{name} . $vhost_url->{path} .' for '. $hostname);
				$num_vhosts++;
				if ($sleep) {
					usleep($sleep);
				} 

				my $query_string = $vhost_url->{query_string} ? $vhost_url->{query_string} : $vhost->{query_string};
				my $response = $vhost_url->{response} ? $vhost_url->{response} : $vhost->{response};
				if ($threads>1) {
					if (scalar(keys %children) == $threads) {
						$LOGGER->debug('Already have '. scalar(keys %children) .' processes for this loop, waiting for one to return');
						# wait for a kid to finish
						my $kid = wait;
						$LOGGER->debug($kid .' returned');
						delete $children{$kid};
					} 

					# birth a new child
					my $pid = fork();
					if ($pid) {
						$LOGGER->debug('Forked a new process ('. $pid .')');
						$children{$pid} = 1;
					} else {
						check_host($vhost_url->{name}, $vhost->{ip}, $vhost->{port}, 
							$vhost_url->{query_string}, $hostname, $vhost_url->{response});
						exit 0;
					}
				} else {
					my $query_string = $vhost_url->{query_string} ? $vhost_url->{query_string} : $vhost->{query_string};
					my $response = $vhost_url->{response} ? $vhost_url->{response} : $vhost->{response};
					check_host($vhost_url->{name}, $vhost->{ip}, $vhost->{port}, 
						$query_string, $hostname, $response, $vhost_url->{path});
				}
			} # Loop all vhost urls
		} # Loop all vhosts

		# Reap all children for this loop if there are any
		if ($threads>1) {
			while (wait>0) {}
			undef %children;
			$LOGGER->debug('All forked processes for the '. $hostname .' process loop have been accounted for');
		}

		# TODO: FIXME if $num_vhosts is 0 then there will be an issue below
		my $end = time();
		$total_time = $end-$start;
		$LOGGER->debug($hostname .' loop took '. $total_time .' seconds');
		# If the amount of time it took us to run / $num_hosts < $MAXTURNAROUNDTIME
		# then update $sleep 
		if ($total_time < $MAXTURNAROUNDTIME) {
			if ($threads>1) {
				$threads--;
				$LOGGER->debug('Decreasing threads used by '. $hostname .' from '. ($threads+1) .' to '.  $threads);
			} else {
				if (($sleep+(10*1000000)) < ($MAXTURNAROUNDTIME*1000000)) {
					$sleep = (($sleep+(10*1000000)/$num_vhosts));
				} else {
					$sleep = (($MAXTURNAROUNDTIME*1000000)/$num_vhosts);
				}
				$LOGGER->debug("Setting sleep time between checks for $hostname to $sleep ms");
			}

		} 

		# If not then it toook longer.
		elsif ($sleep > 0) { 
			# Back off by 10 seconds until we get to 0
			if (($sleep-(10*1000000)) > 0) {
				$sleep = ($sleep-10000000);
			} else {
				$sleep = 0; 
			}
		}
		elsif ($threads == $MAXTHREADSPERHOST) {
			$LOGGER->warn("The $hostname thread is behind by ". 
				($MAXTURNAROUNDTIME-$total_time) ." seconds and is already using ".
				$MAXTHREADSPERHOST ." threads"); }
		else {
			$threads++;
			$LOGGER->debug('Increasing threads used by '. $hostname .' from '. ($threads-1) .' to '.  $threads);
		}
	} # Looping forever, alone and cold on the moon.  Nobody love me.
	
}

sub check_host {
	my ($name, $ip, $port, $query_string, $hostname, $rc, $path) = @_;
	$LOGGER->debug("check_host($name, $ip, $port, \$query_string, $hostname, $rc, $path)");
	my $code = 0;
	my $http = 'http';
	if ($port == 443) {
		$http .= 's';
	}

	my $mech = WWW::Mechanize->new( 
		ssl_opts => { 
			verify_hostname => 0
		} 
	);
	$mech->add_handler('response_redirect' => \&response_redirect);
	$mech->conn_cache(LWP::ConnCache->new);
	$LOGGER->debug('Mechanize browser initialized');

	$hostname =~ /^([^\.]+)/;
	my $short_hostname = $1;

	$mech->add_header(HOST => $name);

	# This is a hack for passing data back and forth betwee the redirection
	# handler, as we want to exit the handler as soon as there is a match of
	# the redirection;
	if ($query_string && $rc =~ /3\d\d/) {
		$LOCATION = $query_string;
	} else {
		$LOCATION = $query_string;
	}
	eval {
		$mech->get($http ."://$ip$path");
	};
	if ($@) {
		$LOGGER->error("Issues (vhost=$name) $@");
	}

	my $response = "$http://$name returned: ";

	# TODO: is this a problem with the special characters in a url?
	if ($LOCATION ne 'matched' && $rc =~ /3\d\d/ ) {
		$LOGGER->warn("\$NO302 query_string: $query_string");
		$LOGGER->warn("\$NO302 LOCATION: $LOCATION");
		$LOGGER->warn("\$NO302 rc: $rc");
    $LOGGER->warn("NO302: ${http}://${ip}${path} (HOST => $name): $LOCATION");
		$response .= " Did NOT $rc to expected location: $query_string";
		$code=2;
	} elsif ($LOCATION eq 'matched' && $rc =~ /3\d\d/) {
		$response .= " $rc to expected location: $query_string";
	} elsif($rc != '200' && $rc == $mech->response()->code()) {
		$response .= " expected $rc";
	} else {
		$response .= $mech->response()->code() .'.';
		if ($mech->response()->code() != $rc) {
			$code=2;
		} else {
			if (
				$query_string &&
				($mech->content() !~ /$query_string/) &&
				($mech->content(format => 'text') !~ /$query_string/) ){
				$response .= ' Response did not match "'. $query_string .'".';
				$code = 3;
			} #if
			else {
				$response .= ' Response matched "'. $query_string .'".';
			} #else
		}	#else
	} #else

  # Aug 29 13:01:43 puppet nagios_vhost.pl: DEBUG - [1472500903] PROCESS_SERVICE_CHECK_RESULT;ampocalypse;ampocalypse.radicaldesigns.org:443 on ampocalypse.radicaldesigns.org;2;https://ampocalypse.radicaldesigns.org returned:  Did NOT 302 to expected location: radicaldesigns.org; radicaldesigns.org
	$LOGGER->debug('['. time() .'] PROCESS_SERVICE_CHECK_RESULT;'. $short_hostname .';'. 
		$name .':'. $port . $path .' on '. $hostname .';'. 
		$code .';'. $response .'; '. $LOCATION);

	if (! open(CMD_FILE, '>>', $CMD_FILE)) {
		$LOGGER->fatal("Could not open $CMD_FILE to append data to: $!");
		die;
	}
	print CMD_FILE '['. time() .'] PROCESS_SERVICE_CHECK_RESULT;'. $short_hostname .';'.
		$name .':'. $port . $path .' on '. $hostname .';'.
		$code .';'. $response ."\n";
	close CMD_FILE;
}

# When this is trigered from process_server_vhosts it will cause the loop to 
# jump out of the sleep if one is being issued.
sub print_statistics {
	use Log::Log4perl qw(:levels);
	my ($host_id, $time, $sleep, $threads) = @_;

	# Make sure we are not called unless we are running in daemon mode
	return if (!$DAEMON);

	# Set up the queries
	my $sth_vhosts = $DBH->prepare(
		"SELECT vhost.vhost_id,vhost.name,count(vhost_alias.name) as vhost_aliases from vhost ".
		"LEFT JOIN vhost_alias ON (vhost.vhost_id = vhost_alias.vhost_id) ".
		"WHERE vhost.host_id = ? ".
		"GROUP BY vhost.vhost_id");

	my $sth_hosts;
	if (defined ($host_id)) {
		$sth_hosts = $DBH->prepare(
			"SELECT host.host_id,host.name,count(vhost.vhost_id) as vhosts from host ".
			"LEFT JOIN vhost ON (vhost.host_id = host.host_id) ".
			"WHERE host.host_id = ? ".
			"GROUP BY host.host_id");
		$sth_hosts->execute($host_id);
		
	} else {
		$sth_hosts = $DBH->prepare(
			"SELECT host.host_id,host.name,count(vhost.vhost_id) as vhosts from host ".
			"LEFT JOIN vhost ON (vhost.host_id = host.host_id) ".
			"GROUP BY host.host_id");
		$sth_hosts->execute();
	}

	# For each host print the number of vhosts and vhost_aliases we are checking
	my $level = $LOGGER->level();
	$LOGGER->level($INFO);
	while (my $host = $sth_hosts->fetchrow_hashref()) {
		my $vhost_aliases = 0;
		$sth_vhosts->execute($host->{host_id});
		while (my $vhost = $sth_vhosts->fetchrow_hashref()) {
			$vhost_aliases += $vhost->{vhost_aliases};
		}
		$LOGGER->info($host->{name} .' '. ($host->{vhosts}+$vhost_aliases) .' checks ('.
			$host->{vhosts} .' vhosts, '. $vhost_aliases ." aliases)");

		if ($host_id) {
			$LOGGER->info($host->{name} .' has a RTT of '. $time .' seconds is using '.
				'a sleep of '. $sleep .' micro seconds, and is utilizing '. $threads 
				.' threads');
		}
	}
	
	$LOGGER->level($level);
}

# get all hosts associated with Drupal, log in and check for module updates
sub get_and_send_web_application_status_to_nagios {

	my $check_drupal_cmd = "check_drupal.pl -p ";
	my $check_wordpress_cmd = "check_wordpress.pl -p ";
	
	my $sth = $DBH->prepare(
	'SELECT host.name as hostname, host.nagios_host_name as nagios_hostname,
		vhost.name as vhostname, vhost.port as port,
		vhost_application.path as path, vhost_application.type as type
		FROM host
		LEFT JOIN vhost ON (host.host_id = vhost.host_id)
		LEFT JOIN vhost_application ON ( vhost.vhost_id = vhost_application.vhost_id)
		WHERE vhost_application.type=?
	');

	$sth->execute('Drupal');
	while (my $result = $sth->fetchrow_hashref()) {
		print "\t". $result->{hostname} ."\$ $check_drupal_cmd ".
			$result->{path} ." --uri=". $result->{vhostname} ."\n"
			if $VERBOSE;

		my $vhosts = sshopen2($result->{hostname}, *READER5, *WRITER5, 
			$check_drupal_cmd . $result->{path} ." --uri=". $result->{vhostname});
		while (my $line = <READER5>) {
			# RETURN CODES:
			# 0-OK, 1-WARNING, 2-CRITICAL, 3-UNKNOWN
			open(NSCA, "|$NSCA -H $NSCA_HOST -c $NSCA_CONFIG") or 
				die "could not start nsca: $NSCA -H $NSCA_HOST -c $NSCA_CONFIG";

			my $rc = 0;
			$rc = 1 if $line =~ /WARNING/;
			$rc = 2 if $line =~ /CRITICAL/;
			$rc = 3 if $line =~ /UNKNOWN/;

			print "\t". $result->{nagios_hostname} ."\t". $result->{vhostname} .':'. 
				$result->{port} .' on '. $result->{hostname} ." ". $result->{type} .
				" Updates\t$rc\t$line"
				if $VERBOSE>1;

			print NSCA $result->{nagios_hostname} ."\t". $result->{vhostname} .':'. 
				$result->{port} .' on '. $result->{hostname} ." ". $result->{type} .
				" Updates\t$rc\t$line";

			close NSCA;
		}
	}
	close READER5;
	close WRITER5;

	$sth->execute('WordPress');
	while (my $result = $sth->fetchrow_hashref()) {

		print "\t". $result->{hostname} ."\$ $check_wordpress_cmd". 
			$result->{path} ."\n"
			if $VERBOSE;

		sshopen2($result->{hostname}, *READER6, *WRITER6, $check_wordpress_cmd .$result->{path});
		while (my $line = <READER6>) {

			# RETURN CODES:
			# 0-OK, 1-WARNING, 2-CRITICAL, 3-UNKNOWN
			open(NSCA, "|$NSCA -H $NSCA_HOST -c $NSCA_CONFIG") or 
				die "could not start nsca: $NSCA -H $NSCA_HOST -c $NSCA_CONFIG";

			my $rc = 0;
			$rc = 2 if $line =~ /CRITICAL/;

			print "\t". $result->{nagios_hostname} ."\t". $result->{vhostname} .':'. 
				$result->{port} .' on '. $result->{hostname} ." ". $result->{type} .
				" Updates\t$rc\t$line"
				if $VERBOSE>1;

			print NSCA $result->{nagios_hostname} ."\t". $result->{vhostname} .':'. 
				$result->{port} .' on '. $result->{hostname} ." ". $result->{type} .
				" Updates\t$rc\t$line";


			close NSCA;
		}
	}
	close READER6;
	close WRITER6;
}

sub usage {
print <<END;
$0 [options]
A tool for managing and monitoring apache vhosts in nagios.
When this is run without the --daemon, --add-web-server, or 
--add-vhost-query-string options this script will poll all configured 
webservers for vhosts, and will update the nagios vhost config files.

--add-web-server <server>          : Adds a new webserver to the local database
                                     that will later be queried for a list of
                                     apache vhosts that it hosts.  The server
                                     name should be accesible by ssh key auth
--get-web-servers                  : Will generate a list of web servers and 
                                     vhosts stored in the application database
--add-vhost-query-string <vhost>   : Adds a new query string for the vhost 
                                     specified by <vhost>, the --query-string
                                     argument is required
--query-string <string>            : The string that will be searched for in
                                     the page response for vhost.  Failure to
                                     find this string will result in a nagios
                                     error.  The default is the vhost name
--nagios-config-dir <dir>          : The directory to place nagios vhost config
                                     files that will be generated from the DB
--daemon                           : Run in daemon mode where vhosts are 
                                     queried and reported on.  In this mode all
                                     output will be sent to syslog in the daemon
                                     context
--external-command-file <file>     : The externaal command file to write 
                                     nagios results to.  Default is
                                     /var/lib/nagios3/rw/nagios.cmd
--update-web-servers [server_list] : Log into each of the web servers 
                                     specified in the optional comma seperated
                                     list of [server_list].  If [server_list] 
                                     is not specified then poll all web servers
                                     configured in the db.
--web-application-status-to-nagios : This flag will log into each host that has
                                     web applications associated with enabled
                                     vhosts and check for available updates.
                                     Installation of check_wordpress and
                                     check_drupal on the remote host is assumed
--nsca-host                        : The NSCA host address to send the results
                                     of --web-application-status-to-nagios to.
                                     DEFAULT: localhost
--nsca-config                      : The send_nsca config to use when sending
                                     results from 
                                     --web-application-status-to-nagios DEFAULT
                                     /etc/send_nsca.cfg
--database                         : The MySQL databasse name to connect to 
                                     DEFAULT: nagios_vhost
--username                         : The MySQL username to connect with 
                                     DEFAULT: nagios_vhost
--password                         : The MySQL password to connect to MySQL 
                                     with. DEFAULT: nagios_vhost
--verbose                          : Repeat this option to increase verbosity
--help                             : This help message
END
}

