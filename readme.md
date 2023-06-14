# SNMP adapter

The __snmp-adapter__ adapter allows the ClearBlade Platform or Edge to function as an SNMP manager. 

The adapter utilizes MQTT topics to provide the mechanism whereby the ClearBlade Platform or Edge can interact with an SNMP network.

# MQTT topic structure
The __snmp-adapter__ adapter utilizes MQTT messaging to communicate with the ClearBlade Platform. The __snmp-adapter__ adapter will subscribe to a specific topic to handle requests from the ClearBlade Platform/Edge to interact with SNMP agents. In addition, the adapter can start an SNMP trap server to receive SNMP traps from SNMP agents and send the SNMP trap data to the ClearBlade Platform or Edge. The topic structures utilized by the __snmp-adapter__ are as follows:

  * Send SNMP request to __snmp-adapter__: {__TOPIC ROOT__}/__{AGENT_NAME}__/request
  * Send SNMP response to Clearblade: {__TOPIC ROOT__}/__{AGENT_NAME}__/response
  * Send SNMP errors to Clearblade: {__TOPIC ROOT__}/__{AGENT_NAME}__/error
  * Send SNMP trap to Platform/Edge: {__TOPIC ROOT__}/__{AGENT_NAME}__/trap

  * Note: If the adapter is unable to determine the agent name, the __{AGENT_NAME}__ part of the topic will contain _unknownAgent_


## ClearBlade Platform dependencies
The SNMP adapter was constructed to communicate with a _System_ defined in a ClearBlade Platform instance. Therefore, the adapter requires a _System_ to have been created within a ClearBlade Platform instance.

Once a system has been created, artifacts must be defined within the ClearBlade Platform system to allow the adapters to function properly. At a minimum: 

  * A device must be created in the Auth --> Devices collection. The device will represent the adapter for authentication purposes. The adapter will use the _name_ and _active key_ values specified in the Auth --> Devices collection to authenticate to the ClearBlade Platform or Edge. 
  * An adapter configuration data collection must be created in the ClearBlade Platform _system_ and populated with the data appropriate to the SNMP adapter. The data collection schema should be as follows:


| Column Name      | Column Datatype |
| ---------------- | --------------- |
| adapter_name     | string          |
| topic_root       | string          |
| adapter_settings | string (json)   |

### adapter_settings
The adapter_settings column will need to contain a JSON object. The object's keys will be the agents' names (SNMP devices) the adapter will send commands. The key values will be a JSON object containing the following attributes:

##### serialNumberOid
* __OPTIONAL__
* The OID represents an SNMP data item that contains the SNMP agent serial number

##### mibModule
* __OPTIONAL__
* The name of the MIB file utilized by the SNMP agent

##### shouldHandleTraps
* A boolean value indicating whether or not the adapter should start an SNMP trap server to process SNMP device traps

##### trapServerPort
* An integer denoting the port number on which the SNMP trap server should listen
* Required if __shouldHandleTraps__ is true

###### snmpAddress
* An string representing the IP address of the SNMP agent where SNMP commands should be sent

###### connectionPort
* An integer denoting the port number of the SNMP agent where SNMP commands should be sent
* __Will default to 161 if not provided__

##### snmpTransport
* Transport protocol to use ("udp" or "tcp") when connecting to the SNMP agent
* __Will default to _udp_ if not provided__

##### snmpVersion
* The SNMP version 
* 1, 2 or 3
* __Will default to 2__

##### snmpCommunity
*	SNMP community string

##### snmpTimeout
* The SNMP query timeout
* __Will default to 2 seconds__

##### snmpExponentialTimeout
* Whether to double timeout in each retry
* __Will default to false__

##### snmpMaxOids
* Maximum number of oids allowed in a Get
* __Will default to 0__

##### snmpMaxRepetitions
* Sets the GETBULK max-repetitions used by BulkWalk
* __Will default to 50__

##### snmpNonRepeaters
* NonRepeaters sets the GETBULK max-repeaters used by BulkWalk
* __Will default to 0__

##### snmpAppOpts
* netsnmp has '-C APPOPTS - set various application specific behaviours'
* Unsure if _snmpAppOpts_ applies to SNMP traps 

##### snmpMsgFlags
*	SNMPV3 MsgFlags
  * Describes authentication, privacy, and whether a report PDU must be sent
* Unsure if _snmpMsgFlags_ applies to SNMP traps

##### snmpSecurityModel
* SecurityModel is an SNMPV3 Security Model
* UserSecurityModel (=3) is the only one implemented
* Unsure if _snmpSecurityModel_ applies to SNMP traps

##### snmpSecurityParameters
* SNMPV3 Security Model parameters struct
* Unsure if _snmpSecurityParameters_ applies to SNMP traps

##### snmpContextEngineID
* SNMPV3 ContextEngineID in ScopedPDU

##### snmpContextName
* SNMPV3 ContextName in ScopedPDU

#### adapter_settings_example
{
  "myFirstSnmpDevice" : {
    "serialNumberOid": ".1.3.6.1.4.1.17095.1.3.4.24",
    "mibModule": "AE-MIB",
    "shouldHandleTraps": true,
    "trapServerPort": 164,
    "snmpAddress": "192.168.1.1",
    "connectionPort": 2164,
    "snmpTransport": "udp",
    "snmpVersion": 2,
	  "snmpCommunity": "public",
    "snmpAppOpts": {"c": true},
  },
  "mySecondSnmpDevice" : {
    "serialNumberOid": ".1.3.6.1.4.1.17095.1.3.4.24",
    "mibModule": "AE-MIB",
    "shouldHandleTraps": true,
    "trapServerPort": 165,
    "snmpAddress": "192.168.1.2",
    "connectionPort": 2165,
    "snmpTransport": "tcp",
    "snmpVersion": 3,
	  "snmpCommunity": "xxyyvvwwn",
    "snmpMsgFlags": 2,
    "snmpSecurityModel": 3,
    "snmpSecurityParameters": {},
    "snmpContextEngineID": "",
    "snmpContextName": ""
  }
}


## Usage

### Executing the adapter

`snmp-adapter -systemKey=<SYSTEM_KEY> -systemSecret=<SYSTEM_SECRET> -platformURL=<PLATFORM_URL> -messagingURL=<MESSAGING_URL> -deviceName=<DEVICE_NAME> -password=<DEVICE_ACTIVE_KEY> -adapterConfigCollection=<COLLECTION_NAME> -logLevel=<LOG_LEVEL>`

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
  * The active key the adapter will use to authenticate to the platform
  * Requires the device to have been defined in the _Auth - Devices_ collection within the ClearBlade Platform __System__
   
   __platformUrl__
  * The URL of the ClearBlade Platform instance the adapter will connect to
  * OPTIONAL
  * Defaults to __http://localhost:9000__

   __messagingUrl__
  * The MQTT URL of the ClearBlade Platform instance the adapter will connect to
  * OPTIONAL
  * Defaults to __localhost:1883__

   __adapterConfigCollection__
  * OPTIONAL 
  * The name of the data collection used to house adapter configuration data
  * Defaults to adapter_config

   __logLevel__
  * The level of runtime logging the adapter should provide
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
The __snmp-adapter__ adapter is dependent upon the ClearBlade Go SDK, its dependent libraries being installed, and the Go SNMP library (github.com/soniah/gosnmp). The __snmp-adapter__ adapter was written in Go and therefore requires Go to be installed (https://golang.org/doc/install).


### Adapter compilation
Follow these steps to compile the adapter for execution:

 1. Retrieve the adapter source code. 
    * ```git clone git@github.com:ClearBlade/snmp-adapter.git```
 2. Navigate to the __SNMP-ADAPTER__ directory.
    * ```cd SNMP-Adapter```
 3. ```go get```
 4. Compile the adapter.
    * ```go build```
    * ```GOARCH=arm GOARM=5 GOOS=linux go build```
    * ```GOARCH=amd64 GOOS=linux go build```

### Payloads

#### SNMP JSON PDU structure
The adapter request and response will contain an SNMP PDU-like JSON structure array. The PDU structure's format will contain the following fields:
##### name
 * The OID in string format
 * ex. '.1.1.1.1.1.1'
##### type
 * The Asn1BER data type, represented as an integer

  | Asn1BER Data Type | Integer Value |
  | ----------------- | ------------- |
  | EndOfContents     | 0 |
  | UnknownType       | 0 |
  | Boolean           | 1 |
  | Integer           | 2 |
  | BitString         | 3 |
  | OctetString       | 4 |
  | Null              | 5 |
  | ObjectIdentifier  | 6 |
  | ObjectDescription | 7 |
  | IPAddress         | 64 |
  | Counter32         | 65 |
  | Gauge32           | 66 |
  | TimeTicks         | 67 |
  | Opaque            | 68 |
  | NsapAddress       | 69 |
  | Counter64         | 70 |
  | Uinteger32        | 71 |
  | OpaqueFloat       | 120 |
  | OpaqueDouble      | 121 |
  | NoSuchObject      | 128 |
  | NoSuchInstance    | 129 |
  | EndOfMibView      | 130 |

##### value
 * The associated OID's value

##### Example JSON PDU
{
  name: '.1.1.1.1.1.1',
  type: 2,
  value: 4
}

#### Currently supported SNMP operations
 * SNMP GET - snmpOperation="get"
 * SNMP GETNEXT - snmpOperation="getnext"
 * SNMP GETBULK (SNMP v2 and v3) - snmpOperation="getbulk"
 * SNMP SET - snmpOperation="set"

#### SNMP request

The attributes included in an SNMP request are as follows:

###### snmpAgent
* The SNMP agent name that should handle the request
* __The agent MUST exist in the adapter_settings column of the adapter_config collection__

###### snmpOIDs
* A JSON PDU array (see format above) the request will be executed against

###### snmpOperation
* The SNMP operation to execute
* One of get, getnext, getbulk, set, walk, walkall, bulkwalk, bulkwalkall


```
{
  "snmpAgent": "MyISPRouter",
  "snmpAgentIP": "192.168.1.1",
  "snmpOIDs": [
    {
      "name": ".1.3.6.1.4.1.9999.1.1.1",
      "type": 2
    }, 
    {
      "name": ".1.3.6.1.4.1.9999.1.1.2",
      "type": 2
    }
  ],
  "snmpOperation": "get
}
```

#### SNMP response
The SNMP operation response will contain the original request and a JSON PDU array representing the data returned by the agent for each OID requested.

```
{
  "request": {
    "snmpAgent": "MyISPRouter",
    "snmpAgentIP": "192.168.1.1",
    "snmpOIDs": [
      {
        "name": ".1.3.6.1.4.1.9999.1.1.1",
        "type": 2
      }, 
      {
        "name": ".1.3.6.1.4.1.9999.1.1.2",
        "type": 2
      }
    ],
    "snmpOperation": "get
    },
    success: true,
    error: '',
    snmpOIDs: [
      {
        name: ".1.3.6.1.4.1.9999.1.1.1",
        type: 2,
        value: 15
      },
      {
        name: ".1.3.6.1.4.1.9999.1.1.2",
        type: 2,
        value: 475
      }
    ]
  }
```

#### SNMP trap
SNMP trap data sent from the adapter will have the following format:

```
{
  "snmpAgent": "MyISPRouter",
  "sourceIP": "192.168.1.1",
  "snmpOIDs": [
    {
      "name": ".1.3.6.1.4.1.9999.1.1.1",
      "type": 2,
      "value": 8
    }, 
    {
      "name": ".1.3.6.1.4.1.9999.1.1.2",
      "type": 2,
      "value": 15
    }
  ],
}
```
