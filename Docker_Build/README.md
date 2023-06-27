# Docker image creation

## Prerequisites

- Building the image requires internet access.

### Creating the Docker image for the SNMP adapter

Clone this repository and execute the following commands to create a docker image for the SNMP adapter:  

- ```docker build --no-cache -f Docker_Build/Dockerfile -t clearblade/snmp-adapter:{version} -t clearblade/snmp-adapter:latest .``` 

# Using the adapter

## Deploying the adapter image

When the docker image has been created, it must be saved and imported into the runtime environment. Execute the following steps to save and deploy the adapter image.

- On the machine where the ```docker build``` command was executed, execute ```docker save clearblade/snmp-adapter:latest > snmp-adapter.tar``` 

- On the server where docker is running, execute ```docker load -i snmp-adapter.tar```

## Executing the adapter

Once you create the docker image, start the SNMP adapter using the following command:

```docker run -d --name socket-listener-adapter --network cb-net --restart always -p {TRAP_SERVER_1_PORT}:{TRAP_SERVER_1_PORT} -p {TRAP_SERVER_2_PORT}:{TRAP_SERVER_2_PORT} clearblade/socket-listener-adapter:{version} -systemKey=<SYSTEM_KEY> -systemSecret=<SYSTEM_SECRET> -platformURL=<PLATFORM_URL> -messagingURL=<MESSAGING_URL> -deviceName=<DEVICE_NAME> -password=<DEVICE_ACTIVE_KEY> -adapterConfigCollection=<COLLECTION_NAME> -logLevel=<LOG_LEVEL>```

   __*Where*__ 

   __systemKey__
  * REQUIRED
  * The system key of the ClearBlade Platform __System__ the adapter will connect to

   __systemSecret__
  * REQUIRED
  * The system secret of the ClearBlade Platform __System__ the adapter will connect to
   
   __deviceName__
  * The device name the adapter will use to authenticate to the ClearBlade Platform
  * Requires the device to have been defined in the _Auth - Devices_ collection within the ClearBlade Platform __System__
  * OPTIONAL
  * Defaults to __snmp-adapter__
   
   __password__
  * REQUIRED
  * The active key the adapter will use to authenticate to the Platform
  * Requires the device to have been defined in the _Auth - Devices_ collection within the ClearBlade Platform __System__
   
   __platformUrl__
  * The ClearBlade Platform instance URL the adapter will connect to
  * OPTIONAL
  * Defaults to __http://localhost:9000__

   __messagingUrl__
  * The ClearBlade Platform instance MQTT URL the adapter will connect to
  * OPTIONAL
  * Defaults to __localhost:1883__

   __adapterConfigCollection__
  * OPTIONAL 
  * The data collection name used to house the adapter configuration data
  * Defaults to adapter_config

   __logLevel__
  * The runtime logging level the adapter should provide
  * Available log levels:
    * fatal
    * error
    * warn
    * info
    * debug
  * OPTIONAL
  * Defaults to __info__

Ex.
```docker run -d --name clearblade/snmp-adapter:1.0.0 --network cb-net --restart always snmp-adapter --systemKey cc9d8bba0bfeeed78595c4dfbb0b --systemSecret CC9D8BBA0BB4F1C5AD8994E6D41B --platformURL https://platform.clearblade.com --messagingURL platform.clearblade.com:1883 --deviceName snmpAdapter --password 01234567890```
