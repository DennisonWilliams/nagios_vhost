#!/usr/bin/perl
use strict;
use warnings;
use DBI;
use Data::Dumper;
use Getopt::Long;
use File::Basename;
use Cwd 'abs_path';
use Net::SSH qw(ssh_cmd sshopen2);
use Net::DNS;

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

    # If the line begins with a #, then skip the line.
    if (substr($_, 0, 1) eq '#') {
      next;
    }

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
$VERBOSE = 0;
$DBFILE = dirname(abs_path($0)) .'/.'. basename($0) .'.db';
$NAGIOSCONFIGDIR = '/etc/nagios3/conf.d/';
$USENSCA = 0;
$CMD_FILE = '/var/lib/nagios3/rw/nagios.cmd';
my $help;

my $result = GetOptions (
	"query-string:s" => \$QUERYSTRING,
	"add-web-server:s" => \$ADDWEBSERVER,
	"get-web-servers" => \$GETWEBSERVERS,
	"add-vhost-query-string:s" => \$ADDVHOSTQUERYSTRING,
	"nagios-config-dir:s" => \$NAGIOSCONFIGDIR,
	"daemon"    => \$DAEMON,
	"use-nsca"    => \$USENSCA,
	"external-command-file:s"    => \$CMD_FILE,
	"verbose+"    => \$VERBOSE,
	"help" => \$help
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
} else {
	#collect_vhosts_from_webservers();
	#generate_check_vhost_config_files();
	generate_nagios_config_files();
}

sub initDB{
	my ($sth, @dat, $schema_version);

	# Make sure the file exists
	# TODO: is there any reason we should be using File::Touch here?	
	#if (!-f $DBFILE) {
		#`touch $DBFILE`;
	#}

	print "Initializing application database (". $DBFILE .")\n"
		if $VERBOSE;	
	# Connect to the database
	# TODO: add RaiseError
	$DBH = DBI->connect("dbi:SQLite:dbname=$DBFILE", "", "",{ 
		RaiseError => 1,
		sqlite_use_immediate_transaction => 1 })
			|| die "Could not connect to database: $DBI::errstr";

	# TODO: this will generate a error if the schema has not been installed yet,
	# but will not fail.
	$sth = $DBH->prepare( 
		"SELECT value FROM variables WHERE `key`='schema_version'"
	);
	if (defined($DBI::errstr) && $DBI::errstr =~ /no such table/) {
		install();
		$sth = $DBH->prepare("INSERT INTO variables(`key`, `value`) values(?, ?)");
		$sth->execute('schema_version', 1);
	} else {
	
		$sth->execute();
		my $ref = $sth->fetchrow_hashref();
		$sth->finish();
		$schema_version = $ref->{'value'};

		if (!defined($schema_version)) {
				install();
				$sth = $DBH->prepare("INSERT INTO variables(`key`, `value`) values(?, ?)");
				$sth->execute('schema_version', 1);
		}
	}

	# Upgrade starts here
	#my $st_schema = $DBH->prepare('UPDATE variables set value = ? where key = ?');
	#if ($schema_version == 1) { 
		# Perform some DB upgrade operations here
		#$st_schema->execute('2', 'schema_version');		
		#$schema_version = 2;
	#}
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
	# be different then what the hoost this script is running from uses to
	# actually ssh to / web client to
	$sth = $DBH->prepare(
		"CREATE TABLE host (
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
			host_id INT NOT NULL,
			last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			name VARCHAR(255),
			ip VARCHAR(15),
			port INT NOT NULL DEFAULT 80,
			enabled INT NOT NULL DEFAULT 1,
			query_string VARCHAR(255),
			FOREIGN KEY(host_id) REFERENCES host(rowid)
	)");
	$sth->execute();
	$sth->finish();

	$sth = $DBH->prepare(
		"CREATE TABLE vhost_alias (
			vhost_id INT NOT NULL,
			last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			name VARCHAR(255),
			FOREIGN KEY(vhost_id) REFERENCES vhost(rowid)
	)");
	$sth->execute();
	$sth->finish();
}

sub add_new_web_server_to_db{
	my ($host) = @_;
	my $sth = $DBH->prepare('INSERT INTO host(name) values(?)') 
		|| die "$DBI::errstr";;
	$sth->execute($host);
	print "inserted $host into the host table\n" 
		if $VERBOSE;
}

sub get_web_servers{
	my $sth = $DBH->prepare('SELECT rowid,name from host')
		|| die "$DBI::errstr";
	my $stv = $DBH->prepare('SELECT vhost_id,name,port,query_string from vhost where host_id=? order by name')
		|| die "$DBI::errstr";
	my $sta = $DBH->prepare('SELECT name from vhost_alias where vhost_id=? order by name') 
		|| die "$DBI::errstr";

	$sth->execute();

	while (my $host = $sth->fetchrow_hashref()) {
		print $host->{name} ."\n";
		$stv->execute($host->{rowid});
		while (my $vhost = $stv->fetchrow_hashref()) {
			$sta->execute($vhost->{rowid});
			my @aliases;
			while (my $alias = $sta->fetchrow_hashref()) {
				push @aliases, $alias->{name};
			}

			my $vhost_str = "\t". $vhost->{name}; 

			if ($#aliases) {
				$vhost_str .= ": ". join(', ', @aliases);
			}

			if (defined($vhost->{query_string})) {
				$vhost_str .= ': '. $vhost->{query_string};
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
	my $sth = $DBH->prepare('SELECT rowid,name from host')
		|| die "$DBI::errstr";;
	my $stv = $DBH->prepare('SELECT * from vhost where host_id=?')
		|| die "$DBI::errstr";;
	my $stvd = $DBH->prepare('UPDATE vhost set enabled=0 where host_id=? and name=? and port=?')
		|| die "$DBI::errstr";;
	my $std = $DBH->prepare('DELETE from vhost_alias where vhost_id=?')
		|| die "$DBI::errstr";;
	my $stvai = $DBH->prepare('INSERT INTO vhost_alias(vhost_id, name) values(?, ?)')
		|| die "$DBI::errstr";;
	my $stvi = $DBH->prepare('INSERT INTO vhost(host_id, name, port, $ip) values(?, ?, ?, ?)')
		|| die "$DBI::errstr";;

	$sth->execute();
	my $get_vhosts_cmd = "/usr/bin/sudo /usr/sbin/apache2ctl -D DUMP_VHOSTS 2>/dev/null|grep namevhost";
	my $get_config_file_cmd = "/bin/cat ";

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

		my $vhosts = ssh_cmd($host->{name}, $get_vhosts_cmd);
		foreach (split(/\n/, $vhosts)) {
			my $vhost_line = $_;
			$vhost_line =~ /port (\d+) namevhost ([^\s]+) \(([^:]+):\d+\)/;
			my $port = $1;
			my $vhost = $2;	
			my $config = $3;
			$vhosts{$vhost}{$port}{config} = $config;

			# Get all of the aliases from the config file
			print "\tGetting the config file for $vhost:$port ($config)...\n" if $VERBOSE;
			#$config = ssh_cmd($host->{name}, $get_config_file_cmd .$config);
			sshopen2($host->{name}, *READER, *WRITER, $config) ||
				die "ssh: $!";

			my $acp = Apache::ConfigParserWithFileHandle->new;
			my $rc = $acp->parse_file(*READER);

			# TODO: some better error handling here may be in order
			if (!$rc) {
				print $acp->errstr ."\n";
				exit;
			}

			my @aliases;
			my $root = $acp->root;
			foreach my $sas ($acp->find_down_directive_names('serveralias')) {
				my @server_names = $acp->find_siblings_directive_names($sas, 'servername');
				my @virtual_hosts = $acp->find_siblings_and_up_directive_names($sas, 'virtualhost');
				my $server_name  = $server_names[0]->value;
				my $virtual_host = $virtual_hosts[0]->value;

				next if ($server_name ne $vhost);
				next if ($virtual_host !~ /([^:]+):$port/);
				$vhosts{$vhost}{$port}{ip} = $1 || $ip;
				my $sa = $sas->value;
				foreach my $alias (split(/\s+/, $sa)) {
					$alias =~ s/^\*\./meow./;
					push(@aliases, $alias);
				}
			}

			print "\tFound the aliases for $vhost:$port: ". join(', ', @aliases) ."...\n" if $VERBOSE;
			$vhosts{$vhost}{$port}{aliases} = \@aliases;
		}

		# We can't just delete the hosts because users may have added 
		# query_strings for them that need to be persistent.
		# Disable all vhosts that exist in the database that were not returned
		$stv->execute($host->{rowid});
		while (my $vhost = $sth->fetchrow_hashref()) {
			if (!defined($vhosts{$vhost->{name}}{$vhost->{port}})) {
				print "\t". $vhost->{name} .":". $vhost->{port} ." is no longer hosted on ". $host->{name}
					.". Removing it from the DB...\n" if $VERBOSE;
				$stvd->execute($host->{rowid}, $vhost->{name}, $vhost->{port});
				next;
			}

			# Update all vhost entries that were returned and are different then what
			# is in the database

			# TODO: what about vhosts that are enabled again?
			print "\tRemoving aliases for ". $vhost->{name} .":". $vhost->{port} ."...\n" if $VERBOSE;
			$std->execute($vhost->{rowid});

			foreach(@{$vhosts{$vhost->{name}}{$vhost->{port}}{aliases}}) {
			  print "\nInserting ". $_ ." as alias for ". $vhost->{name} .":". $vhost->{port} ."...\n" if $VERBOSE;	
				$stvai->execute($vhost->{rowid}, $_);
			}
			delete($vhosts{$vhost->{name}}{$vhost->{port}});
		}

		# Insert all new vhosts
		foreach (keys %vhosts) {
			my $vhost = $_;
			foreach (keys %{$vhosts{$vhost}}) {
				my $port = $_;
				print "Adding new vhost: $vhost:$port (". $host->{rowid} .")...\n" if $VERBOSE;
				$stvi->execute($host->{rowid}, $vhost, $port, $vhosts{$vhost}{port}{ip});
				my $rowid = $DBH->func('last_insert_rowid');

				foreach (@{$vhosts{$vhost}{$port}{aliases}}) {
					print "Adding $_ as alias for $vhost:$port...\n" if $VERBOSE;
					$stvai->execute($rowid, $_);
				}
			}
		}

	}
	
}

sub generate_check_vhost_config_files {
	my $sth = $DBH->prepare("SELECT rowid,name from host")
		|| die "$DBI::errstr";

	my $stv = $DBH->prepare(
		"SELECT vhost.rowid,name,port,query_string FROM vhost WHERE host_id = ?")
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
		$stv->execute($host->{rowid});
		while (my $vhost = $stv->fetchrow_hashref()) {
			print HOSTFILE $vhost->{name} ." ".$vhost->{port} ." ". 
				(defined($vhost->{query_string})?$vhost->{query_string}:'') ."\n";
			$stva->execute($vhost->{rowid});
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
	my $sth = $DBH->prepare('SELECT rowid FROM vhost WHERE name = ?')
		|| die "$DBI::errstr";;
	$sth->execute($ADDVHOSTQUERYSTRING);
	my $vhost = $sth->fetchrow_hashref();
	die 'Can not add a query string for a vhost that has not been added yet. '.
		$ADDVHOSTQUERYSTRING .' does not exist in the database'
		if (!$vhost->{rowid});

	# TODO: we should prolly sanitize this data we are inserting
	$sth = $DBH->prepare('UPDATE vhost set query_string = ? WHERE name = ?')
		|| die "$DBI::errstr";;
	$sth->execute($QUERYSTRING, $ADDVHOSTQUERYSTRING);

	print "Added query string:\"$QUERYSTRING\" for $ADDVHOSTQUERYSTRING...\n"
		if $VERBOSE;
}

sub generate_nagios_config_files {
	my $sth = $DBH->prepare("SELECT rowid,name from host")
		|| die "$DBI::errstr";

	my $stv = $DBH->prepare(
		"SELECT vhost.rowid,name,port,query_string FROM vhost WHERE host_id = ? and enabled=1")
		|| die "$DBI::errstr";

	my $stva = $DBH->prepare(
		"SELECT name FROM vhost_alias WHERE vhost_id = ?")
		|| die "$DBI::errstr";

	# Create a new config file for each host
	# The format of the config file is our modified version of the check_vhosts
	# script: http://exchange.nagios.org/directory/Plugins/Web-Servers/check_vhosts/details
	$sth->execute();
	while (my $host = $sth->fetchrow_hashref()) {
		# TODO: do this
		$host->{name} =~ /^([^\.]+)/;
		my $short_hostname = $1;
		print "Creating vhost config file for ". $host->{name} ."(". $NAGIOSCONFIGDIR . $host->{name} ."_vhosts.cfg...\n" 
			if $VERBOSE;
		open (HOSTFILE, '+>', $NAGIOSCONFIGDIR . $host->{name} .'_vhosts.cfg')
			|| die('Could not open the vhost config file ('. $NAGIOSCONFIGDIR . $host->{name} .'_vhosts.cfg' .'): '. $?);
		$stv->execute($host->{rowid});
		while (my $vhost = $stv->fetchrow_hashref()) {
			print HOSTFILE "define service {\n".
				"\tuse generic-service-passive-no-notification-no-perfdata\n".
				"\tservice_description ". $vhost->{name} .':'. $vhost->{port} .' on '. $host->{name} ."\n".
				"\tservicegroups ". $host->{name} ."_vhosts\n".
				"\thost_name $short_hostname\n}\n\n";

			print HOSTFILE "define servicedependency {\n".
				"\thost_name $short_hostname\n".
				"\tservice_description HTTP\n".
				"\tdependent_host_name $short_hostname\n".
				"\tdependent_service_description ". $vhost->{name} .':'. $vhost->{port} .' on '. $host->{name} ."\n".
				"\texecution_failure_criteria n\n".
				"\tnotification_failure_criteria w,u,c,p\n}\n\n";

			$stva->execute($vhost->{rowid});
			while (my $vahost = $stva->fetchrow_hashref()) {
				print HOSTFILE "define service {\n".
					"\tuse generic-service-passive-no-notification-no-perfdata\n".
					"\tservice_description ". $vahost->{name} .':'. $vhost->{port} .' on '. $host->{name} ."\n".
					"\tservicegroups ". $host->{name} ."_aliases\n".
					"\thost_name $short_hostname\n}\n\n";

				print HOSTFILE "define servicedependency {\n".
					"\thost_name $short_hostname\n".
					"\tservice_description HTTP\n".
					"\tdependent_host_name $short_hostname\n".
					"\tdependent_service_description ". $vahost->{name} .':'. $vhost->{port} .' on '. $host->{name} ."\n".
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

	my $logger = get_logger("Daemon");
	$logger->add_appender($appender);
	$logger->level($WARN);
	#$logger->level($DEBUG);
	$logger->debug('Logger initialized');
	Proc::Daemon::Init;
	initDB();
	$logger->debug('Application daemonized');

	my $continue = 1;
	$SIG{TERM} = sub { $continue = 0 };

	# Loop across all of the vhosts and alias' in the database and submit 
	# Passive checks for them
	my $sth = $DBH->prepare("SELECT rowid,name from host")
		|| die "$DBI::errstr";

	my $stv = $DBH->prepare(
		"SELECT vhost.rowid,name,port,ip,query_string FROM vhost WHERE host_id = ? and enabled=1")
		|| die "$DBI::errstr";

	my $stva = $DBH->prepare(
		"SELECT name FROM vhost_alias WHERE vhost_id = ?")
		|| die "$DBI::errstr";

	while ($continue) {
		$logger->debug('Main loop entered');

		eval {
			$sth->execute();
		};
		if ($@) {
			$logger->fatal($@);
			die $@;
		}
		while (my $host = $sth->fetchrow_hashref()) {

			# Moving the mech object into the hoost loop will at most create 
			# an object of size equal to (<num_vhosts> + <num_aliases>) *
			# <memory_overhead_per_page_for_mech>
			my $mech = WWW::Mechanize->new( 
				ssl_opts => { 
					#SSL_version => 'SSLv3',
					verify_hostname => 0
				} 
			);
			$mech->add_handler('response_redirect' => \&response_redirect);
			$mech->conn_cache(LWP::ConnCache->new);
			$logger->debug('Mechanize browser initialized');

			$host->{name} =~ /^([^\.]+)/;
			my $short_hostname = $1;

			$logger->debug('Processing vhosts for '. $host->{name});
			$stv->execute($host->{rowid});
			while (my $vhost = $stv->fetchrow_hashref()) {
				my ($response, $code, $perfdata, $passive_check);
				$code = 0;
				my $http = 'http';
				if ($vhost->{port} == 443) {
					$http .= 's';
				}

				my $ip = $vhost->{ip};
				$mech->add_header(HOST => $vhost->{name});
				# This should automatically handle redirects
				$logger->debug("polling $http://$ip HOST -> ". $vhost->{name} ."\n");
				eval {
					$mech->get($http ."://$ip");
				};
				if ($@) {
					$logger->error("Issues: $@. vhost=". $vhost->{name});
				}

				my $query_string = defined($vhost->{query_string})?$vhost->{query_string}:$vhost->{name};
				$response = "$http://". $vhost->{name} ." returned: ". $mech->response()->code() .'.';
				if ($mech->response()->code() != 200) {
					$code=2;
				} else {
					if (
						($mech->content() !~ /$query_string/) &&
						($mech->content( format => 'text' ) !~ /$query_string/) ){
						$response .= ' Response did not match "'. $query_string .'".';
						$code = 3;
					}
				}	

				$logger->debug('['. time() .'] PROCESS_SERVICE_CHECK_RESULT;'. $host->{name} .';'. 
					$vhost->{name} .':'. $vhost->{port} .' on '. $host->{name} .';'. 
					$code .';'. $response);

				if (! open(CMD_FILE, '>>', $CMD_FILE)) {
					$logger->fatal("Could not open $CMD_FILE to append data to: $!");
					die;
				}
				print CMD_FILE '['. time() .'] PROCESS_SERVICE_CHECK_RESULT;'. $short_hostname .';'.
          $vhost->{name} .':'. $vhost->{port} .' on '. $host->{name} .';'.
          $code .';'. $response ."\n";
				close CMD_FILE;
				
				$stva->execute($vhost->{rowid});
				while (my $vahost = $stva->fetchrow_hashref()) {
					$code = 0;
					$mech->add_header(HOST => $vahost->{name});
					# This should automatically handle redirects
					eval {
						$mech->get($http ."://$ip");
					};
					if ($@) {
						$logger->error("Issues: $@. vhost: ". $vahost->{name});
					}

					$response = "$http://". $vahost->{name} ." returned: ". $mech->response()->code() .'.';
					if ($mech->response()->code() != 200) {
						$code=2;
					} else {
						if (
							($mech->content() !~ /$query_string/) &&
							($mech->content(format => 'text') !~ /$query_string/) ){
							$response .= ' Response did not match "'. $query_string .'".';
							$code = 3;
						}
					}	

					$logger->debug('['. time() .'] PROCESS_SERVICE_CHECK_RESULT;'. $host->{name} .';'. 
						$vahost->{name} .':'. $vhost->{port} .' on '. $host->{name} .';'. 
						$code .';'. $response);

					if (! open(CMD_FILE, '>>', $CMD_FILE)) {
						$logger->fatal("Could not open $CMD_FILE to append data to: $!");
						die;
					}
					print CMD_FILE '['. time() .'] PROCESS_SERVICE_CHECK_RESULT;'. $short_hostname .';'.
						$vahost->{name} .':'. $vhost->{port} .' on '. $host->{name} .';'.
						$code .';'. $response ."\n";
					close CMD_FILE;
				
				} # $stva while loop
			} # $stv while loop
		} # $sth while loop
	} # continue while loop
}

# If the handler returns an HTTP::Request object we'll start over with processing this request instead.
sub response_redirect {
	my($response, $ua, $h) = @_;

	my $url;
	if ($response->header('Location')) {
		if ($response->header('Location') !~ /^http/) {
			$response->request()->as_string() =~ /GET\s+(http[^:]*):/;
			$url = $1 .'://'. $response->request()->header('Host');
			if ($response->header('Location') !~ /^\//) {
				$url .= "/";
			}
			$url .= $response->header('Location');
		} else {
			$url = $response->header('Location');
		}

		# Remove the HOST Header
		$ua->delete_header('HOST');
		# Update the uri with the Location Header value
		# create and return a HTTP::Request object
		# TODO: is there ever a situation where this would not be a GET?
		return HTTP::Request->new( "GET", $url);
	}
	return;
}

sub debug_response {
 	my ($file_name, $content) = @_;
	open (TMP, , '>', "/tmp/$file_name")
		or die("Could not open /tmp/$file_name for writing");

	print TMP $content;

	close TMP;
}

sub usage {
print <<END;
$0 [options]
A tool for managing and monitoring apache vhosts in nagios.
When this is run without the --daemon, --add-web-server, or 
--add-vhost-query-string options this script will poll all configured 
webservers for vhosts, and will update the nagios vhoost config files.

--add-web-server <server>          : Adds a new webserver to the local database
                                     that will later be queried for a list of
                                     apache vhosts that it hosts.  The server
                                     name should be accesible by ssh key auth
--get-web-servers                  : Will generate a list oof web servers and 
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
--verbose                          : Repeat this option to increase verbosity
--help                             : This help message
END
}
