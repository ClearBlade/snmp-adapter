Instructions for use:

1. Copy snmp-adapter.etc.default file into /etc/default, name the file "snmp-adapter"
2. Modify the values of the variables defined in the /etc/default/snmp-adapter file to match your system
3. Copy snmp-adapter.etc.initd file into /etc/init.d, name the file "snmp-adapter"
4. From a terminal prompt, execute the following commands:
	3a. chmod 755 /etc/init.d/snmp-adapter
	3b. chown root:root /etc/init.d/snmp-adapter
	3c. update-rc.d snmp-adapter defaults 85

If you wish to start the adapter, rather than reboot, issue the following command from a terminal prompt:

	/etc/init.d/snmp-adapter start