# Snort IDS/IPS Implementation - Final Report
Group 4: Robert Castellano, Rodnee Yang, Sykong Yang
<br>

# Introduction
We have been implementing and configuring Snort as an IDS/IPS with a custom ruleset for logging network traffic. Below is a list of the tools we are utilizing for this implementation:
- Snort - The engine
- Splunk - Graphical User Interface
- PulledPork - Ruleset manager
- OpenAppID - Plugin for application-layer detection

## Full Tool Descriptions
### Snort 3
The intrusion engine that makes up the backbone of our IDS. Version 3 of Snort features faster, more efficient rules and gives users more control. It also includes support for multiple packet processing threads, shared configuration and attribute table, pluggable key components, autodetects services for portless configuration, autogenerates reference documentation, supports sticky buffers in rules, and provides better cross-platform support than previous versions.
<br>

### Splunk
Splunk is the GUI used for Snort. It can provides users with dashboards, enables saved searches, and provides reports, event types, tags and event search interfaces. [1](https://www.splunk.com/) <a href="https://www.splunk.com/" target="_blank">example</a>

### PulledPork 3
PulledPork is a Snort component that is used for rulesets. It uses the LightSPD package and “allows a single ruleset package to adapt the rules it can run to the version of the engine running on the system and allows users to select a default policy for the ruleset.” [2](https://blog.snort.org/2021/06/pulledpork-3-rule-updating-for-snort-3.html)
<br>

### OpenAppID
OpenAppID is Snort’s application layer network security plugin. It is used to detect, monitor, and manage application usage and enables Snort “to be used as an open source, customizable application firewall or next-generation firewall.”[3](https://www.cybertraining365.com/cybertraining/Topics/OpenAppID#:~:text=OpenAppID%20is%20an%20application%2Dlayer,source%20intrusion%20detection%20system%20Snort.)  OpenAppID can be used to detect malicious applications or rogue application use and can implement application blacklisting, limit application usage and enforce conditional controls.
<br>

# Installation
This section will cover the steps for installing and configuring each of the tools used in a Linux environment using Ubuntu 18 or 20. This also applies to WSL2. 
<br>

## Prerequisite
Begin by ensuring we have an up-to-date package manager and timezone:
```bash
$ sudo apt-get update && sudo apt-get dist-upgrade -y
$ sudo dpkg-reconfigure tzdata
```
<br>

## Snort3
Create a Snort directory where we can install all of our files (we will do this at the root directory):

```bash
$ mkdir ~/snort_src
$ cd ~/snort_src
```

Next, we need to install packages that snort uses to run (these go in our snort directory we just created):

```bash
$  sudo apt-get install -y build-essential autotools-dev libdumbnet-dev libluajit-5.1-dev libpcap-dev zlib1g-dev pkg-config libhwloc-dev cmake liblzma-dev openssl libssl-dev cpputest libsqlite3-dev libtool uuid-dev git autoconf bison flex libcmocka-dev libnetfilter-queue-dev libunwind-dev libmnl-dev ethtool libjemalloc-dev
```

Safeclib (helps prevent network buffer overflows):
```bash
$ cd ~/snort_src
$ wget https://github.com/rurban/safeclib/releases/download/v3.7.1/safeclib-3.7.1.tar.gz
$ tar -xzvf safeclib-3.7.1.tar.gz
$ cd safeclib-3.7.1
$ ./configure
$ make
$ sudo make install
```

### Hyperscan packages (for Hyperscan, which snort uses for fast pattern matching):
<br>

PCRE(Perl Compatible Regular Expressions):  
```bash
$ cd ~/snort_src
$ wget wget https://sourceforge.net/projects/pcre/files/pcre/8.45/pcre-8.45.tar.gz
$ tar -xzvf pcre-8.45.tar.gz
$ cd pcre-8.45
$ ./configure
$ make
$ sudo make install
```

gperftools (google performance tools):
```bash
$ cd ~/snort_src
$ wget https://github.com/gperftools/gperftools/releases/download/gperftools-2.10/gperftools-2.10.tar.gz
$ tar xzvf gperftools-2.10.tar.gz
$ cd gperftools-2.10
$ ./configure
$ make
$ sudo make install
```

Ragel:
```bash
$ cd ~/snort_src
$ wget http://www.colm.net/files/ragel/ragel-6.10.tar.gz
$ tar -xzvf ragel-6.10.tar.gz
$ cd ragel-6.10
$ ./configure
$ make
$ sudo make install
```

Boost (just downloading, no installing here):
```bash
$ cd ~/snort_src
$ wget https://boostorg.jfrog.io/artifactory/main/release/1.77.0/source/boost_1_77_0.tar.gz
$ tar -xvzf boost_1_77_0.tar.gz
```

And now we can install Hypsercan for Snort (from Boost):
```bash
$ cd ~/snort_src
$ wget https://github.com/intel/hyperscan/archive/refs/tags/v5.4.0.tar.gz
$ tar -xvzf v5.4.0.tar.gz
$ mkdir ~/snort_src/hyperscan-5.4.0-build
$ cd hyperscan-5.4.0-build/
$ cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBOOST_ROOT=~/snort_src/boost_1_77_0/ ../hyperscan-5.4.0
$ make
$ sudo make install
```

Flatbuffers (data serialization): 
```bash
$ cd ~/snort_src
$ wget https://github.com/google/flatbuffers/archive/refs/tags/v23.1.21.tar.gz -O flatbuffers-v23.1.21.tar.gz
$ tar -xzvf flatbuffers-v23.1.21.tar.gz
$ mkdir flatbuffers-build
$ cd flatbuffers-build
$ cmake ../flatbuffers-v23.1.21
$ make
$ sudo make install
```

Data Aquisition Library (DAQ, will help us use Snort as IPS later):
```bash
$ cd ~/snort_src
$ wget https://github.com/snort3/libdaq/archive/refs/tags/v3.0.10.tar.gz -O libdaq-3.0.10.tar.gz
$ tar -xzvf libdaq-3.0.10.tar.gz
$ cd libdaq-3.0.10
$ ./bootstrap
$ ./configure
$ make
$ sudo make install
```

Update shared libraries in Linux:
```bash
$ sudo ldconfig
```

Finally, install snort:
```bash
$ cd ~/snort_src
$ wget https://github.com/snort3/snort3/archive/refs/tags/3.1.55.0.tar.gz -O snort3-3.1.55.0.tar.gz
$ tar -xzvf snort3-3.1.55.0.tar.gz
$ cd snort3-3.1.55.0
$ ./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc --enable-jemalloc
$ cd build
$ make
$ sudo make install
```
<br>

The snort executable should now be installed at `/usr/local/`. Verify it runs properly with: 
```bash
$ /usr/local/bin/snort -V
```
The output should include everything we just downloaded:
```bash
   ,,_     -*> Snort++ <*-
  o"  )~   Version 3.1.55.0
   ''''    By Martin Roesch & The Snort Team
           http://snort.org/contact#team
           Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using DAQ version 3.0.10
           Using LuaJIT version 2.1.0-beta3
           Using OpenSSL 1.1.1f  31 Mar 2020
           Using libpcap version 1.9.1 (with TPACKET_V3)
           Using PCRE version 8.45 2021-06-15
           Using ZLIB version 1.2.11
           Using Hyperscan version 5.4.0 2023-02-11
           Using LZMA version 5.2.4
```
Snort is now installed.
<br>

## Configuring Snort
Create directories and files that Snort will use for rules.
```bash
$ sudo mkdir /usr/local/etc/rules
$ sudo mkdir /usr/local/etc/so_rules/
$ sudo mkdir /usr/local/etc/lists/
$ sudo touch /usr/local/etc/rules/local.rules
$ sudo touch /usr/local/etc/lists/default.blocklist
$ sudo mkdir /var/log/snort
```

We have created a local.rules file, this is where we can create our own custom rules. Let's do this and run snort with it:

This uses linux's default "vi" text editor with sudo permissions, you can use another text editor as long as you have read/write permissions:
```bash
$ sudo vi /usr/local/etc/rules/local.rules
```

Once you have access to the file, create a rule and save:
```
1|  alert icmp any any -> any any ( msg:"ICMP Traffic Detected"; sid:10000001; metadata:policy security-ips alert; )
```

Run Snort once with the local.rules file to validate:
```bash
$ snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/rules/local.rules
```

Run Snort passively, this will have Snort listening for traffic on the network interface:
```bash
$ sudo snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/rules/local.rules -i eth0 -A alert_fast -s 65535 -k none
```

Once loaded, it will show that it's listening after displaying:
```bash
Commencing packet processing
++ [0] eth0
```

On another terminal, test Snort by using the `ping` command.
```bash
$ ping 8.8.8.8
```

You should see an alert to the console that is running Snort. Stop pinging and Snort with `Ctrl+C`.
This was a test rule, you can delete or comment it out as it is essentially reading all traffic.
<br>

Now we'll update our Snort config file to read our rules by default:

Open the config file (again you can use your own text editor)
```bash
$ sudo vi /usr/local/etc/snort/snort.lua
```

Around line 170 you will see `ips` section, uncomment it and enable our rules:
```lua
ips = 
{
    enable_builtin_rules = true,
    include = RULE_PATH .. "/local.rules",
    variable = default_variables
}
```
Test the config file with Snort:
```bash
$ snort -c /usr/local/etc/snort/snort.lua
```
If you want, run Snort again without calling the local rule file this time, it should still work because we included in the configuration (the `-i eth0` parameter tells snort which interface to listen on, you can check yours with `ip link show`).
```bash
$ sudo snort -c /usr/local/etc/snort/snort.lua -i eth0 -A alert_fast -s 65535 -k none
```
Open another terminal and ping again to see alerts.

## PulledPork3
Return to the Snort directory and we can begin installing PulledPork3.
```bash
$ cd ~/snort_src
$ git clone https://github.com/shirkdog/pulledpork3.git
```

Enter the pulledpork directory we just cloned and copy the necessary files into our system:
```bash
$ cd ~/snort_src/pulledpork3
$ sudo mkdir /usr/local/bin/pulledpork3
$ sudo cp pulledpork.py /usr/local/bin/pulledpork3
$ sudo cp -r lib/ /usr/local/bin/pulledpork3
$ sudo chmod +x /usr/local/bin/pulledpork3/pulledpork.py
$ sudo mkdir /usr/local/etc/pulledpork3
$ sudo cp etc/pulledpork.conf /usr/local/etc/pulledpork3/
```

We can verify that pulledpork runs the same way as we did for Snort:
```bash
$ /usr/local/bin/pulledpork3/pulledpork.py -V
```

Output should look like: 
```bash
PulledPork v3.0.0.2
https://github.com/shirkdog/pulledpork3
_____ ____
----,\ ) PulledPork v3.0.0-BETA
--==\\ / Lowcountry yellow mustard bbq sauce is the best bbq sauce. Fight me.
--==\\/
.-~~~~-.Y|\\_ Copyright (C) 2021 Noah Dietrich, Colin Grady, Michael Shirk
@_/ / 66\_ and the PulledPork Team!
| \ \ _(")
\ /-| ||'--' Rules give me wings!
\_\ \_\\
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```
<br>

We will be utilizing the LightSPD ruleset, a pre-made ruleset on top of our own custom rules. It's free, but you must create an account with [Snort](https://snort.org) to get an oinkcode that will let you activate it. Otherwise, you can also enable the free, no-code, community ruleset.

Modify the pulledpork config file to enable the chosen ruleset:
```bash
$ sudo vi /usr/local/etc/pulledpork3/pulledpork.conf
```

Near the beginning of the file should be where you can enable rulesets (enter code on line 8 for LightSPD):
```bash
3| community_ruleset = false
4| registered_ruleset = false
5| LightSPD_ruleset = true
...
8| oinkcode = <code here>
```

For downloading/creating blocklists enable them on line 12-13:
```bash
12| snort_blocklist = true
13| et_blocklist = true
```

Point pulledpork to the Snort executable and your local rules (uncomment this line): 
```bash
30| snort_path = /usr/local/bin/snort
...
62| local_rules = /usr/local/etc/rules/local.rules
```

Run pulledpork, which will compile a new rule file with the configurations we just set.
```bash
$ sudo /usr/local/bin/pulledpork3/pulledpork.py -c /usr/local/etc/pulledpork3/pulledpork.conf
```

Earlier we changed or Snort configuration to read our local rule file. Now, we can change that to read our new pullpork rule file, which also contains our local rule file.

Open the snort config file again:
```bash
$ sudo vi /usr/local/etc/snort/snort.lua
```

Change the `ips` section this time to read our pulledpork rules (around line 170):
```lua
ips = 
{
    enable_builtin_rules = true,
    include = RULE_PATH .. "/pulledpork.rules",
    variable = default_variables
}
```

Let's run Snort once to make sure it works. We also include a new parameter that points to a file that pulledpork references:
```bash
$ snort -c /usr/local/etc/snort/snort.lua --plugin-path /usr/local/etc/so_rules/
```

### Snort Plugin Configuration
We will update a few things in our Snort configuration again before we start running.

We'll set our HOME_NET variable which will allow rules to read what are local subnet is (check for your network with `ip link show`).
```bash
24| HOME_NET = '10.0.0.0/20'
```

Uncomment the "reputation" block around line 100 and enable the blocklist:
```lua
repuation = 
{
    blocklist = BLACK_LIST_PATH .. "/default.blocklist",
}
```

We'll enable hyperscan, add these lines after the "reputation" block but before "section 3: configure bindings":
```lua
search_engine = { search_method = "hyperscan" }

detection = {
hyperscan_literals = true,
pcre_to_regex = true
}

-- 3.configure bindings
```

Save the config file, run snort again to validate it works:
```bash
$ snort -c /usr/local/etc/snort/snort.lua --plugin-path /usr/local/etc/so_rules/
```

### JSON Alerts Plugin
We want to start logging the traffic we capture with our rules, this plugin will let us do that and store them in a json format. Also, this will allow us to import the logs in our SIEM tool (Splunk) later.

Once again, we just have to enable this in our Snort configuration.

Open the Snort config file:
```bash
$ sudo vi /usr/local/etc/snort/snort.lua
```

Enable the alert_json plugin with optional fields (this shows all possible fields) found in section 7:
```lua
 alert_json =
{
    file = true,
    limit = 100,
    fields = 'seconds action class b64_data dir dst_addr dst_ap dst_port eth_dst eth_len \
    235 eth_src eth_type gid icmp_code icmp_id icmp_seq icmp_type iface ip_id ip_len msg mpls \
    236 pkt_gen pkt_len pkt_num priority proto rev rule service sid src_addr src_ap src_port \
    237 target tcp_ack tcp_flags tcp_len tcp_seq tcp_win tos ttl udp_len vlan timestamp',
}
```

Now, alerts will be logged into the file `/var/log/snort/alert_json.txt`

Run Snort passively and generate requests to test this again. If you want, instead of pinging, try using a browser or tool to request an address instead. Check the alert_json.txt file to see the alerts:
```bash
cat /var/log/snort/alert_json.txt
```

## OpenAppID
This plugin allows Snort to detect traffic in the application layer. This is sometimes referred to as next-generation detection.

Return to the Snort directory we created in the beginning to install this:
```bash
$ cd ~/snort_src/
$ wget https://snort.org/downloads/openappid/24625 -O OpenAppId-24625.tgz
$ tar -xzvf OpenAppId-24625.tgz
$ sudo cp -R odp /usr/local/lib/
```

We'll update our Snort configuration to use OpenAppID (around line 100):
```lua
appid =
{
    app_detector_dir = '/usr/local/lib',
}
```

Let's make sure our Snort configuration is still valid, run snort once:
```bash
$ snort -c /usr/local/etc/snort/snort.lua --plugin-path /usr/local/etc/so_rules/
```

Now we can add a rule to our local rule file (which pulledpork will include when we run Snort.):
```bash
$ sudo vi /usr/local/etc/rules/local.rules
```
```bash
alert tcp any any -> any any ( msg:"Facebook Detected"; appids:"Facebook"; sid:10000002; metadata:policy security-ips alert; )
```

Before we test our new custom rule, we need to update pulledpork again so that it sees the changes we just made to our local rule file. Run pulledpork with it's config file:
```bash
$ sudo /usr/local/bin/pulledpork3/pulledpork.py -c /usr/local/etc/pulledpork3/pulledpork.conf
```

Now we can run Snort passively and make a request to "Facebook" or whatever appid you set the rule to listen for.

Make the requests with `ping`, `wget`, or a browser.
Check your alert_json.txt file for logs of the detected traffic.

We can capture additional statistic information with OpenAppID with plugins from the Snort Extras repository. Let's get the repository and downloading the "appid_lister" package that gives us additional appid statistics in JSON format.
```bash
$ cd ~/snort_src/
$ wget https://github.com/snort3/snort3_extra/archive/refs/tags/3.1.56.0.tar.gz -O snort3_extra-3.1.56.0.tar.gz
$ tar -xzvf snort3_extra-3.1.56.0.tar.gz
$ cd snort3_extra-3.1.56.0/
$ ./configure_cmake.sh --prefix=/usr/local
$ cd build
$ make
$ sudo make install
```

Now that we've got the Snort Extras, let's enable appid_listener plugin in our Snort configuration. Add these lines under the `appid` block around line 100:
```lua
appid_listener =
{
json_logging = true,
file = "/var/log/snort/appid-output.log",
}
```

At this point, we can run snort with our new plugins and rules, and the full command will be:
```bash
$ sudo snort -c /usr/local/etc/snort/snort.lua --plugin-path=/usr/local/lib/snort_extra --plugin-path=/usr/local/etc/so_rules
```

To run snort passively, add the interface parameters:
```bash
$ sudo /usr/local/bin/snort -c /usr/local/etc/snort/snort.lua --plugin-path=/usr/local/lib/snort/plugins/extra/search_engines/ --plugin-path /usr/local/etc/so_rules/ -s 65535 -k none -l /var/log/snort -i eth0 -m 0x1b
```

## Splunk
Now that we have Snort running with rulesets from pulledpork and OpenAppID, we can choose to use additional software to give us a useful graphical interface with analytical tools. We have installed and enabled this on our systems. We will also install Apache to run a server. The steps (with pictures included) used for installation of these tools can be found at page 18 of this [guide from Snort's official website.](https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/012/147/original/Snort_3.1.8.0_on_Ubuntu_18_and_20.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAU7AK5ITMJQBJPARJ%2F20230411%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230411T214338Z&X-Amz-Expires=172800&X-Amz-SignedHeaders=host&X-Amz-Signature=bb787a637f18a90888b47bb1c611b8a3055ec0304dbe63da1ad541180d11913b) [4](https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/012/147/original/Snort_3.1.8.0_on_Ubuntu_18_and_20.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAU7AK5ITMJQBJPARJ%2F20230411%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230411T214338Z&X-Amz-Expires=172800&X-Amz-SignedHeaders=host&X-Amz-Signature=bb787a637f18a90888b47bb1c611b8a3055ec0304dbe63da1ad541180d11913b)

The alerts that are logged to our alert_json.txt file can be seen on the Splunk interface.

We'll add some additional configuration for Splunk that will accept our Snort Extra OpenAppID statistics:
```bash
$ sudo vi /opt/splunk/etc/apps/TA_Snort3_json/local/inputs.conf
```

Add this to the existing conf file, don't delete the other lines:
```bash
[monitor:///var/log/snort/*appid-output.log*]
sourcetype = snort3:openappid:json
```

Restart your splunk, and search in the search bar with:
> search sourcetype="snort3:openappid:json"
<br>

## LibDAQ and IPS
Before we finish the setup, let's recall libdaq, the Data Aquisition Library we installed earlier. We can use this to simulate the IPS behaviour of our system.

We can begin by checking our available DAQ modules: 
```bash
$ snort --daq-list
```

The beginning of the output should look like: 
```bash
Available DAQ modules:
afpacket(v7): live inline multi unpriv
 Variables:
  buffer_size_mb <arg> - Packet buffer space to allocate in megabytes
  debug - Enable debugging output to stdout
  fanout_type <arg> - Fanout loadbalancing method
  fanout_flag <arg> - Fanout loadbalancing option
  use_tx_ring - Use memory-mapped TX ring
bpf(v1): inline unpriv wrapper
dump(v5): inline unpriv wrapper
```

We will use the first module, `afpacket` in our testing.

Run Snort passively in `inline` mode using the afpacket DAQ module by adding a new flag and parameter to our command: `-Q --daq afPacket`

The full command would look like this (don't need to run it yet):
```bash
$ sudo /usr/local/bin/snort -c /usr/local/etc/snort/snort.lua -Q --daq afpacket --plugin-path=/usr/local/lib/snort/plugins/extra/search_engines/ --plugin-path /usr/local/etc/so_rules/ -s 65535 -k none -l /var/log/snort -i eth0 -m 0x1b
```
Let's add a new rule to our local rules that can show how we can stop traffic. We have been using the "alert" action in the header of our rules. We can now use [actions](https://docs.snort.org/rules/headers/actions) like "drop" to test our ability to stop traffic. Go to our local rules and add a new rule:
(use any text editor)
```bash
$ sudo vi /usr/local/etc/rules/local.rules
```

Add rule:
```
drop tcp any any -> any any ( msg: "Facebook Traffic Blocked"; appids:"Facebook"; sid:10000003; metadata:policy security-ips drop; )
```

Save this and update pulledpork with our new rule:
```bash
$ sudo /usr/local/bin/pulledpork3/pulledpork.py -c /usr/local/etc/pulledpork3/pulledpork.conf
```

You should now be able to run Snort and test for traffic detection and prevention. 

# Running the Software
There were a lot of commands to keep track of as the installations added up. Here is an ordered list of the essential commands to run the application.

1. Run Snort: 
   ```bash
   $ sudo /usr/local/bin/snort -c /usr/local/etc/snort/snort.lua -Q --daq afpacket --plugin-path=/usr/local/lib/snort/plugins/extra/search_engines/ --plugin-path /usr/local/etc/so_rules/ -s 65535 -k none -l /var/log/snort -i eth0 -m 0x1b
   ```
2. Run the Apache server:
   ```bash
   $ sudo service apache2 <start, stop, restart, status>
   ```
3. Run Splunk:
   ```bash
   $ sudo /opt/splunk/bin/splunk <start, stop, restart, status>
   ```
4. Make requests through a browser or the terminal, watch for logs on splunk or the alert_json.txt file.

When making network requests, changing the `action` of your custom rule headers should change the behavior of the software. If you are `alerting`, the traffic should be logged. If you are performing a `drop`, the request should not be successful. Test different rules as you wish.

# References
Most of our references come from reading [documentation and guides](https://snort.org/documents) on the [Snort website](https://snort.org).

### Websites
1. [Snort](https://docs.snort.org)
2. [Splunk](https://www.splunk.com/)
3. [PulledPork (from Snort)](https://blog.snort.org/2021/06/pulledpork-3-rule-updating-for-snort-3.html)
4. [OpenAppID (info)](https://www.cybertraining365.com/cybertraining/Topics/OpenAppID#:~:text=OpenAppID%20is%20an%20application%2Dlayer,source%20intrusion%20detection%20system%20Snort.)
5. [Setup guide](https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/012/147/original/Snort_3.1.8.0_on_Ubuntu_18_and_20.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAU7AK5ITMJQBJPARJ%2F20230411%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230411T214338Z&X-Amz-Expires=172800&X-Amz-SignedHeaders=host&X-Amz-Signature=bb787a637f18a90888b47bb1c611b8a3055ec0304dbe63da1ad541180d11913b)
6. [IPS with AFPacket](https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/000/013/original/Snort_IPS_using_DAQ_AFPacket.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAU7AK5ITMJQBJPARJ%2F20230411%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230411T214347Z&X-Amz-Expires=172800&X-Amz-SignedHeaders=host&X-Amz-Signature=8d3b00e9a54283622133e6ba744ed4914b41a0d6ab461fe20891f53108a1510a)
7. [Extra IPS (from Snort)](https://docs.snort.org)
8. [Rules](https://docs.snort.org/rules/)
9. [Rule Actions](https://docs.snort.org/rules/headers/actions)
10. [Rule Infographic](https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/000/116/original/Snort_rule_infographic.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAU7AK5ITMJQBJPARJ%2F20230411%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230411T233118Z&X-Amz-Expires=172800&X-Amz-SignedHeaders=host&X-Amz-Signature=5c05602c0472901973272bfce666ddb5ba1335e9d78a50d7b4b579727312f8b6)

### Packages
1. [PulledPork](https://github.com/shirkdog/pulledpork)
2. [PCRE](https://sourceforge.net/projects/pcre/files/pcre/8.45/pcre-8.45.tar.gz/download)
3. [safeclib](https://github.com/rurban/safeclib)
4. [gperftools](https://github.com/gperftools/gperftools)
5. [Ragel](http://www.colm.net/open-source/ragel/)
6. [Boost](https://boostorg.jfrog.io/ui/artifactSearchResults?name=boost&type=artifacts)
7. [FlatBuffers](https://github.com/google/flatbuffers)
8. [Hyperscan](https://github.com/intel/hyperscan)
9. [LibDAQ](https://github.com/snort3/libdaq)
