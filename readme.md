# SNMP Adapter

The __snmpAdapter__ adapter provides the ability for the ClearBlade platform or ClearBlade Edge to function as a SNMP manager. 

The adapter utilizes MQTT topics to provide the mechanism whereby the ClearBlade Platform or ClearBlade Edge can interact with a SNMP network.

# MQTT Topic Structure
The __snmpAdapter__ adapter utilizes MQTT messaging to communicate with the ClearBlade Platform. The __snmpAdapter__ adapter will subscribe to a specific topic in order to handle requests from the ClearBlade Platform/Edge to 

publish data to Cloud Pub/Sub. Additionally, the __snmpAdapter__ adapter will publish messages to MQTT topics in order to provide the ClearBlade Platform/Edge with data received from a Cloud Pub/Sub topic subscription. The topic structures utilized by the xDot adapter are as follows:

  * Send SNMP Request to __snmpAdapter__: {__TOPIC ROOT__}/request
  * Send SNMP Response to Clearblade: {__TOPIC ROOT__}/response
  * Send SNMP errors to Clearblade: {__TOPIC ROOT__}/error
  * Send SNMP trap to platform/edge: {__TOPIC ROOT__}/trap


 * TODO - Determine how we handle traps with messaging
 * TODO - Should we have a topic structure that includes the operation? (snmp/get, snmp/trap)



## ClearBlade Platform Dependencies
The xDot adapter was constructed to provide the ability to communicate with a _System_ defined in a ClearBlade Platform instance. Therefore, the adapter requires a _System_ to have been created within a ClearBlade Platform instance.

Once a System has been created, artifacts must be defined within the ClearBlade Platform system to allow the adapters to function properly. At a minimum: 

  * A device needs to be created in the Auth --> Devices collection. The device will represent the adapter, or more importantly, the xDot device or MultiTech Conduit gateway on which the adapter is executing. The _name_ and _active key_ values specified in the Auth --> Devices collection will be used by the adapter to authenticate to the ClearBlade Platform or ClearBlade Edge. 
  * An adapter configuration data collection needs to be created in the ClearBlade Platform _system_ and populated with the data appropriate to the xDot adapter. The schema of the data collection should be as follows:


| Column Name      | Column Datatype |
| ---------------- | --------------- |
| adapter_name     | string          |
| topic_root       | string          |
| adapter_settings | string (json)   |

### adapter_settings
The adapter_settings column will need to contain a JSON object containing the following attributes:

##### shouldHandleTraps
* A boolean value indicating whether or not the adapter should start a SNMP trap server in order to process SNMP traps from devices


#### adapter_settings_example
{
  "shouldHandleTraps": true
}

## Usage

### Executing the adapter

`snmpAdapter -systemKey=<SYSTEM_KEY> -systemSecret=<SYSTEM_SECRET> -platformURL=<PLATFORM_URL> -messagingURL=<MESSAGING_URL> -deviceName=<DEVICE_NAME> -password=<DEVICE_ACTIVE_KEY> -adapterConfigCollectionID=<COLLECTION_ID> -logLevel=<LOG_LEVEL>`

   __*Where*__ 

   __systemKey__
  * REQUIRED
  * The system key of the ClearBLade Platform __System__ the adapter will connect to

   __systemSecret__
  * REQUIRED
  * The system secret of the ClearBLade Platform __System__ the adapter will connect to
   
   __deviceName__
  * The device name the adapter will use to authenticate to the ClearBlade Platform
  * Requires the device to have been defined in the _Auth - Devices_ collection within the ClearBlade Platform __System__
  * OPTIONAL
  * Defaults to __snmpAdapter__
   
   __password__
  * REQUIRED
  * The active key the adapter will use to authenticate to the platform
  * Requires the device to have been defined in the _Auth - Devices_ collection within the ClearBlade Platform __System__
   
   __platformUrl__
  * The url of the ClearBlade Platform instance the adapter will connect to
  * OPTIONAL
  * Defaults to __http://localhost:9000__

   __messagingUrl__
  * The MQTT url of the ClearBlade Platform instance the adapter will connect to
  * OPTIONAL
  * Defaults to __localhost:1883__

   __adapterConfigCollectionID__
  * REQUIRED 
  * The collection ID of the data collection used to house adapter configuration data

   __logLevel__
  * The level of runtime logging the adapter should provide.
  * Available log levels:
    * fatal
    * error
    * warn
    * info
    * debug
  * OPTIONAL
  * Defaults to __info__


## Setup
---
The __snmpAdapter__ adapter is dependent upon the ClearBlade Go SDK and its dependent libraries being installed as well as the Go SNMP library (github.com/soniah/gosnmp). The __snmpAdapter__ adapter was written in Go and therefore requires Go to be installed (https://golang.org/doc/install).


### Adapter compilation
In order to compile the adapter for execution, the following steps need to be performed:

 1. Retrieve the adapter source code  
    * ```git clone git@github.com:ClearBlade/GooglePubSubAdapter.git```
 2. Navigate to the __SNMP-ADAPTER__ directory  
    * ```cd GooglePubSubAdapter```
 3. ```go get -u github.com/ClearBlade/Go-SDK```
    * This command should be executed from within your Go workspace
 4. ```go get -u github.com/soniah/gosnmp```
 5. Compile the adapter
    * ```go build -o snmpAdapter```

### Payloads

#### SNMP Operations
 * SNMP GET
 * SNMP GETNEXT
 * SNMP GETBULK (SNMP v2 and v3)
 * SNMP SET
 * SNMP GET-RESPONSE
 * SNMP WALK
 * SNMP TRAP
 * SNMP NOTIFICATION (SNMP v2 and v3)
 * SNMP INFORM (SNMP v2 and v3)
 * SNMP REPORT (SNMP v2 and v3)


#### SNMP Get
	Version1  SnmpVersion = 0x0
	Version2c SnmpVersion = 0x1
	Version3  SnmpVersion = 0x3

```
{
  snmpAddress: ,
  snmpPort: 161,
  snmpOIDs: [],
  snmpVersion: 2,
  snmpCommunity: 
  snmpOperation: "get", //get, getnext, getbulk, set
  snmpGetBulkNonRepeaters:    //The first N objects can be retrieved with a simple getnext command
  snmpGetBulkMaxRepetitions:  //Attempt up to M getnext operations to retrieve the remaining objects
}
```

#### SNMP Set
```
{

}
```

