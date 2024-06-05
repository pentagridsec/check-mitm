Introduction
=============

This directory contains check scripts to monitor unexpected infrastructure changes with the aim of finding
potential Machine-in-the-Middle situations. These scripts are Nagios/Icinga scripts. They can be run as probes
from your monitoring station or as stand-alone scripts.

The following approaches are implemented:

* ``check_traceroute.py``: This script implements a traceroute for IPv4 or IPv6 using TCP to a destination host and
  port(s). It establishes a TCP connection using increasing TTL values and traces the hops towards the destination
  host:port. The script compares the last N hops from the current route against a list of expected routes. You can pass
  these expected last N hosts via command line or via a configuration file. You can specify multiple ports.
  It is expected that the route to any port follows the expected last hops.

* ``check_jarm.py``: Salesforces once implemented a fingerprinting for SSL/TLS servers, known as
  `JARM <https://github.com/salesforce/jarm>`_. To fingerprint a SSL/TLS server, the tool sends several
  SSL/TLS Client Hello messages and looks at the corresponding Server Hello messages to fingerprint the
  server implementation. The results are then hashed. This check script allows you to compare a server's
  fingerprint against an expected fingerprint.

The entire story and background is explained in our blog post at:
https://www.pentagrid.ch/en/blog/domain-verification-bypass-prevention-caa-accounturi/

Preventive is better than reactive!

Installation
=============

``check_traceroute.py``
-------------------------

* To install dependencies on a Debian-style Linux, run:

::

    apt install python3-scapy python3-seccomp python3-cap-ng

* There is also a ``requirements.txt`` if you prefer this approach, but I would recommend using the libaries from your package system.

* Install the script ``check_traceroute.py`` on your monitoring station, for example under
  ``/usr/local/bin/check_traceroute.py`` and ensure the script has proper file permissions:

::

   FILE=/usr/local/bin/check_traceroute.py
   chown root:nagios $FILE
   chmod 750 $FILE

* For Icinga: The tool needs a raw socket, which requires elevated privileges. Setting Linux Capabilities on a Python
  script does not work. So we could use `capsh` as a wrapper, but it requires elevated privileges as well and need
  to be allowed in sudo as well. Therefore, we allow the ''nagios'' user to run the `check_traceroute.py`
  script with ''sudo'' and without password (to compensate the risk a bit, we use SECCOMP and drop capabilities
  within the script):

::
   
  FILE=/etc/sudoers.d/icinga_check_traceroute
  echo 'nagios ALL=(root) NOPASSWD:/usr/local/bin/check_traceroute.py' > $FILE
  chown root:root $FILE
  chmod 440 $FILE

* If you want to use the script from Icinga, define the check command. Depending on your setup, edit for
  example ``/etc/icinga2/conf.d/commands_check_traceroute.conf``:

::

    object CheckCommand "traceroute" {
      import "plugin-check-command"

      command = [ "sudo", "/usr/local/bin/check_traceroute.py", "--last-hops-config", "/usr/local/etc/check_traceroute.conf" ]
      # You may add:
      #   "--disable-seccomp",
      #   "--disable-cap-dropping",

      arguments = {
        "--target" = "$traceroute_target$"
        "--port" = {
          value = "$traceroute_ports$"
          repeat_key = true
        }
      }
    }


``check_jarm.py``
------------------

* To install dependencies on Debian-style Linux, run:

::

    apt install python3-scapy

* Install the script ``check_jarm.py`` on your monitoring station, for example under ``/usr/local/bin/check_jarm.py`` and ensure the script has proper file permissions:

::

   FILE=/usr/local/bin/check_jarm.py
   chown root:nagios $FILE
   chmod 750 $FILE
   
* For Icinga: The tool needs a raw socket, which requires elevated privileges and using Linux Capabilities is not that easy. Therefore, we allow the ''nagios'' user to run this specific script with ''sudo'' and without password:

::
   
  FILE=/etc/sudoers.d/icinga_check_jarm
  echo 'nagios ALL=(root) NOPASSWD:/usr/local/bin/check_jarm.py' > $FILE
  chown root:root $FILE
  chmod 440 $FILE
  

* If you want to use the script from Icinga, define the check command. Depending on your setup, edit for example ``/etc/icinga2/conf.d/commands_check_jarm.conf``:

::

    object CheckCommand "jarm" {
      import "plugin-check-command"

      command = [ "/usr/local/bin/check_jarm.py",
              "--hostname", "$jarm_hostname$",
              "--target", "$jarm_target$",
              "--port", "$jarm_port$",
              "--expected-hash", "$jarm_expected_hash$" ]

      if (vars.jarm_socks5_host) {
        command += [ "--socks5-host", "$jarm_socks5_host$"]
      }
      if (vars.jarm_socks5_port) {
        command += [ "--socks5-port", "$jarm_socks5_port$" ]
      }

    }




Configuration
==============

``check_traceroute.py``
-------------------------

* If you want to use the script from Icinga, add a configuration file for Icinga, for example
  ``/etc/icinga2/conf.d/services_traceroute.conf``. The target is specified via an IPv4 or IPv6 address, so it will
  work in DNS round-robin environments.

::

    object Service "traceroute-www.example.org" {
      import "generic-service-internet"
      host_name = "www.example.org"
      check_command = "traceroute"

      vars.traceroute_target = "192.168.23.42"
      vars.traceroute_ports = "80 443"
    }

* Run ''mtr'', ''traceroute'', ''traceroute6'' or another tool to determine the last hops of your systems.
  
* If you want to use a config file for the expected routes, adjust the example from ``last_hops.conf.sample``
  and store it in the file system of your test station, for example as ``/usr/local/etc/check_traceroute.conf``
  and fix file permissions:

::
   
  FILE=/usr/local/etc/check_traceroute.conf
  chown root:root $FILE
  chmod 640 $FILE


``check_jarm.py``
------------------

* If you want to use the script from Icinga, add a configuration file for Icinga, for example
  ``/etc/icinga2/conf.d/services_traceroute.conf``. The target is specified via an IPv4 or IPv6 address, so it will
  work in DNS round-robin environments.

::

    object Service "jarm-www.example.org" {
      import "generic-service-internet"
      host_name = "www.example.org"
      check_command = "jarm"

      vars.jarm_hostname = "aspecificvhost.example.org"
      vars.jarm_target = "192.168.23.42"
      vars.jarm_port = "443"
      vars.jarm_expected_hash = "28d28d28d00028d00042d42d000000d2e61cae37a95f75ef00cafe1337ca523"
      # you could set a SOCKS5 proxy as well
      # vars.jarm_socks5_host = "localhost"
      # vars.jarm_socks5_port = "8080"
    }

* To determine JARM hashes, run for example the following command. Here, the target is specified as IP address to also
  connect to a specific address if you use round-robin addresses or similar things. The hostname is used for SNI. We
  assume that the hash is from your server and not already from a MITM.

::

   /usr/local/bin/check_jarm.py --target 45.10.26.156 --hostname www.pentagrid.ch --port 443 --show
   JARM: 28d28d28d00028d00042d42d000000d2e61cae37a985f75ecafb81b33ca523


Copyright and Licence
=====================

``check_traceroute.py`` was developed by Martin Schobert <martin@pentagrid.ch> and
published under a 3-clause BSD licence.

``check_jarm.py`` was developed by Martin Schobert <martin@pentagrid.ch> and
published under a 3-clause BSD licence. It is derived from the `jarm.py <https://github.com/salesforce/jarm>`_ script,
which was developed by John Althouse, Andrew Smart, RJ Nunaly, Mike Brady and Caleb Yu and which is copyrighted by
salesforce.com, inc and published under a BSD 3-Clause license as well.

Please read the the license header in the corresponding files for further details.
