Instructions for use:

1. Copy snmp-adapter.service file into /usr/lib/systemd/system/
2. Modify the values of the variables defined on line 8 (ExecStart=)
4. From a terminal prompt, execute the following commands:
	3a. chmod 644 /usr/lib/systemd/system/snmp-adapter.service
	3b. chown root:root /usr/lib/systemd/system/snmp-adapter.service
	3c. sudo systemctl daemon-reload

If you wish to start the adapter, rather than reboot, issue the following command from a terminal prompt:

	sudo systemctl start snmp-adapter.service