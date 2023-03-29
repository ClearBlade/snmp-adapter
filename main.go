package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"syscall"
	"time"

	adapter_library "github.com/clearblade/adapter-go-library"
	"github.com/clearblade/mqtt_parsing"
	mqttTypes "github.com/clearblade/mqtt_parsing"
	"github.com/gosnmp/gosnmp"
	snmp "github.com/gosnmp/gosnmp"
)

type snmpAgentMapType map[string]snmpAgentSettingsType

type snmpAgentSettingsType struct {
	ShouldHandleTraps bool   `json:"shouldHandleTraps"`
	TrapServerPort    uint16 `json:"trapServerPort"`
	Target            string `json:"snmpAddress"`
	ConnectionPort    uint16 `json:"connectionPort"`
	Transport         string `json:"snmpTransport"` //Transport protocol to use ("udp" or "tcp"); if unset "udp" will be used.
	//SNMP Version - 1, 2 or 3
	SnmpVersion uint8 `json:"snmpVersion"`

	//SNMP Community string
	SnmpCommunity string `json:"snmpCommunity"`

	//timeout for the SNMP Query
	SnmpTimeout uint `json:"snmpTimeout"`

	//number of retries to attempt within timeout
	SnmpRetries int `json:"snmpRetries"`

	//Double timeout in each retry
	SnmpExponentialTimeout bool `json:"snmpExponentialTimeout"`

	//maximum number of oids allowed in a Get
	SnmpMaxOids int `json:"snmpMaxOids"`

	// MaxRepetitions sets the GETBULK max-repetitions used by BulkWalk*
	// Unless MaxRepetitions is specified it will use defaultMaxRepetitions (50)
	// This may cause issues with some devices, if so set MaxRepetitions lower.
	// See comments in https://github.com/soniah/gosnmp/issues/100
	SnmpMaxRepetitions uint32 `json:"snmpMaxRepetitions"`

	// NonRepeaters sets the GETBULK max-repeaters used by BulkWalk*
	// (default: 0 as per RFC 1905)
	SnmpNonRepeaters int `json:"snmpNonRepeaters"`

	// netsnmp has '-C APPOPTS - set various application specific behaviours'
	//
	// - 'c: do not check returned OIDs are increasing' - use AppOpts = map[string]interface{"c":true} with
	//   Walk() or BulkWalk(). The library user needs to implement their own policy for terminating walks.
	SnmpAppOpts map[string]interface{} `json:"snmpAppOpts"`

	// MsgFlags is an SNMPV3 MsgFlags - Describes Authentication, Privacy, and whether a report PDU must be sent
	SnmpMsgFlags uint8 `json:"snmpMsgFlags"`

	// SecurityModel is an SNMPV3 Security Model, UserSecurityModel (=3) is the only one implemented
	SnmpSecurityModel uint8 `json:"snmpSecurityModel"`

	// SecurityParameters is an SNMPV3 Security Model parameters struct
	SnmpSecurityParameters map[string]interface{} `json:"snmpSecurityParameters"`

	// ContextEngineID is SNMPV3 ContextEngineID in ScopedPDU
	SnmpContextEngineID string `json:"snmpContextEngineID"`

	// ContextName is SNMPV3 ContextName in ScopedPDU
	SnmpContextName string `json:"snmpContextName"`
}

type snmpAdapterRequestType struct {
	SnmpAgent     string            `json:"snmpAgent"`
	SnmpOIDs      []snmpJsonPDUType `json:"snmpOIDs"`
	SnmpOperation string            `json:"snmpOperation"` //The SNMP operation to invoke. One of get, getnext, getbulk, set, walk, walkall, bulkwalk, bulkwalkall
}

type snmpAdapterResponseType struct {
	Request  snmpAdapterRequestType `json:"request"`
	Success  bool                   `json:"success"`
	Error    string                 `json:"error"`
	SnmpOIDs []snmpJsonPDUType      `json:"snmpOIDs"`
}

type snmpTrapType struct {
	SnmpAgent string            `json:"snmpAgent"`
	Target    string            `json:"sourceIP"`
	SnmpOIDs  []snmpJsonPDUType `json:"snmpOIDs"`
}

type snmpJsonPDUType struct {
	// The value to be set by the SNMP set, or the value when
	// sending a trap
	Value interface{} `json:"value"`

	// Name is an oid in string format eg ".1.3.6.1.4.9.27"
	Name string `json:"name"`

	// The type of the value eg Integer
	Type int `json:"type"`
}

const (
	defaultTopicRoot          = "snmp"
	snmpGetOperation          = "get"
	snmpGetNextOperation      = "getnext"
	snmpGetBulk               = "getbulk"
	snmpSetOperation          = "set"
	snmpGetResponseOperation  = "getresponse"  //TODO:Not implemented, sent by SNMP agents
	snmpTrapOperation         = "trap"         //TODO:Not implemented, sent by SNMP agents
	snmpNotificationOperation = "notification" //TODO:Not implemented, sent by SNMP agents
	snmpInformOperation       = "inform"       //TODO:Not implemented, sent by SNMP agents
	snmpReportOperation       = "report"       //TODO:Not implemented, SNMP v3 only
	snmpWalkOperation         = "walk"         //TODO:
	snmpWalkAllOperation      = "walkall"      //TODO:
	snmpBulkWalkOperation     = "bulkwalk"     //TODO:
	snmpBulkWalkAllOperation  = "bulkwalkall"  //TODO:
)

var (
	//Adapter command line arguments
	adapterName     = "snmp-adapter"
	logLevel        string //Defaults to info
	adapterConfig   *adapter_library.AdapterConfig
	adapterSettings snmpAgentMapType
	tickerLength    = time.Second * 60 * 15 //15 minute timer to refresh adapter settings

	//gosnmp specific variables
	snmpAgents  = map[string]interface{}{}
	trapServers = map[string]interface{}{}
)

func main() {
	fmt.Println("Starting snmpAdapter...")
	var err error

	err = adapter_library.ParseArguments(adapterName)
	if err != nil {
		log.Fatalf("[FATAL] Failed to parse arguments: %s\n", err.Error())
	}

	adapterConfig, err = adapter_library.Initialize()
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize: %s\n", err.Error())
	}

	processAdapterSettings()

	//Start a timer to periodically re-initialize the adapter_library to re-retrieve the adapter settings
	log.Printf("[INFO] Creating ticker of %d seconds to refresh the adapter settings", tickerLength)
	initTicker := time.NewTicker(tickerLength)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-initTicker.C:
				adapter_library.FetchAdapterConfig()
				processAdapterSettings()
			case <-quit:
				initTicker.Stop()
				return
			}
		}
	}()

	//Connect to the MQTT broker and subscribe to the request topic
	err = adapter_library.ConnectMQTT(adapterConfig.TopicRoot+"/+/request", cbMessageHandler)
	if err != nil {
		log.Fatalf("[FATAL] Failed to connect MQTT: %s\n", err.Error())
	}

	// wait for signal to stop/kill process to allow for graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	sig := <-c

	log.Printf("[INFO] OS signal %s received, gracefully shutting down adapter.\n", sig)
	//Stop the timer
	log.Println("[DEBUG] Stopping the initTicker")
	close(quit)

	//Close all trap servers
	log.Println("[DEBUG] Closing all trap servers")
	if len(trapServers) > 0 {
		for _, trapServer := range trapServers {
			trapServer.(*snmp.TrapListener).Close()
		}
	}

	os.Exit(0)
}

func processAdapterSettings() {
	newSettings := snmpAgentMapType{}
	err := json.Unmarshal([]byte(adapterConfig.AdapterSettings), &newSettings)
	if err != nil {
		log.Fatalf("[FATAL] Failed to parse Adapter Settings: %s\n", err.Error())
	}

	//Remove agents and trap servers that are no longer needed
	cleanUpAgentsAndTrapServers(newSettings)

	//Create agents and trap servers based on the new settings
	for key, agentSettings := range newSettings {
		//First validate the settings
		if ok, error := agentSettingsAreValid(agentSettings); ok {
			//Recreate all agents and trap servers if settings change
			if agentExists := agentExists(key); !agentExists || agentSettingsHaveChanged(key, adapterSettings[key], agentSettings) {
				//Stop and delete the existing trap server
				if trapServerExists(key) {
					log.Printf("[DEBUG] Deleting trap server for agent %s\n", key)
					trapServers[key].(*snmp.TrapListener).Close()
					delete(trapServers, key)
				}

				if agentExists {
					log.Printf("[DEBUG] Deleting snmp agent for agent %s\n", key)
					delete(snmpAgents, key)
				}
				log.Printf("[INFO] Creating snmp agent for agent %s\n", key)
				createAgent(key, agentSettings)

				if agentSettings.ShouldHandleTraps {
					log.Printf("[INFO] Starting trap server on port %d for agent %s\n", agentSettings.TrapServerPort, key)
					go createTrapServer(key, agentSettings)
				}
			}
		} else {
			log.Printf("[Error] Invalid settings for agent: %s\n", error.Error())
		}
	}

	adapterSettings = newSettings
}

// This function is invoked whenever a message is received on the {adapterConfig.TopicRoot}/request topic
func cbMessageHandler(message *mqttTypes.Publish) {
	log.Println("[INFO] cbMessageHandler - request received")
	log.Printf("[DEBUG] handleRequest - Json payload received: %s\n", string(message.Payload))

	var jsonPayload snmpAdapterRequestType
	if err := json.Unmarshal(message.Payload, &jsonPayload); err != nil {
		log.Printf("[ERROR] handleRequest - Error encountered unmarshalling json: %s\n", err.Error())
		sendErrorResponse(jsonPayload, err.Error())
	} else {
		handleRequest(message.Topic, jsonPayload)
	}
}

// This function is responsible for processing requests sent to the adapter
func handleRequest(topic mqtt_parsing.TopicPath, payload snmpAdapterRequestType) {
	if payload.SnmpAgent != "" {
		if agentExists(payload.SnmpAgent) {
			if connection, err := getSnmpConnection(payload.SnmpAgent); err != nil {
				sendErrorResponse(payload, "Error creating SNMP Connection: "+err.Error())
			} else {
				if err := executeSnmpOperation(connection, payload); err != nil {
					sendErrorResponse(payload, err.Error())
				}
			}
		} else {
			log.Printf("[ERROR] agent with name %s does not exist. Cannot connect to agent", payload.SnmpAgent)
		}
	} else {
		log.Println("[ERROR] snmpAgent not specified in request. Cannot execute SNMP operation")
	}
}

// This function is responsible for publishing data to the specified topic
func cbPublish(topic string, data string) error {
	log.Printf("[INFO] cbPublish - Publishing to topic %s\n", topic)
	error := adapter_library.Publish(topic, []byte(data))
	if error != nil {
		log.Printf("[ERROR] cbPublish - Unable to publish to topic: %s due to error: %s\n", topic, error.Error())
		return error
	}

	log.Printf("[DEBUG] publish - Successfully published message to topic %s\n", topic)
	return nil
}

// This function is responsible for creating a connection to the SNMP server
func createAgent(agentName string, settings snmpAgentSettingsType) {
	//We need to dereference the pointer so that we do a deep copy, otherwise we
	//end up modifying the reference and changing the values of other agents
	params := *snmp.Default

	params.Target = settings.Target

	if settings.ConnectionPort > 0 {
		params.Port = settings.ConnectionPort
	}

	if settings.Transport != "" {
		params.Transport = settings.Transport
	}

	if settings.SnmpCommunity != "" {
		params.Community = settings.SnmpCommunity
	}

	if settings.SnmpTimeout > 0 {
		params.Timeout = time.Duration(settings.SnmpTimeout) * time.Second
	}

	params.Version = convertSnmpVersion(settings.SnmpVersion)
	params.ExponentialTimeout = settings.SnmpExponentialTimeout

	if settings.SnmpRetries > 0 {
		params.Retries = settings.SnmpRetries
	}

	if settings.SnmpMaxOids > 0 {
		params.MaxOids = settings.SnmpMaxOids
	}

	if settings.SnmpMaxRepetitions > 0 {
		params.MaxRepetitions = settings.SnmpMaxRepetitions
	}

	if settings.SnmpNonRepeaters > 0 {
		params.NonRepeaters = settings.SnmpNonRepeaters
	}

	if settings.SnmpAppOpts != nil {
		params.AppOpts = settings.SnmpAppOpts
	}

	if params.Version == snmp.Version3 {
		// 	MsgFlags SnmpV3MsgFlags
		if settings.SnmpMsgFlags > 0 {
			params.MsgFlags = snmp.SnmpV3MsgFlags(settings.SnmpMsgFlags)
		}

		if settings.SnmpSecurityModel > 0 {
			params.SecurityModel = snmp.SnmpV3SecurityModel(settings.SnmpSecurityModel)
		}
		//TODO: Implement these as needed
		// 	SecurityParameters SnmpV3SecurityParameters
		// 	ContextEngineID string
		// 	ContextName string

	}

	if logLevel == "debug" {
		params.Logger = snmp.NewLogger(log.New(os.Stdout, "", 0))
	}
	snmpAgents[agentName] = &params

	log.Printf("[DEBUG] createAgent - Agent created %+v\n", params)
	log.Printf("[DEBUG] createAgent - SNMP version set to %+v\n", params.Version)
}

func getSnmpConnection(agentName string) (*snmp.GoSNMP, error) {
	return snmpAgents[agentName].(*snmp.GoSNMP), snmpAgents[agentName].(*gosnmp.GoSNMP).Connect()
}

// This function is responsible for returning a successful SNMP response to the invoking client
func sendResponse(returnData snmpAdapterResponseType) {
	response, err := json.Marshal(returnData)

	if err == nil {
		if returnData.Request.SnmpAgent != "" {
			cbPublish(adapterConfig.TopicRoot+"/"+returnData.Request.SnmpAgent+"/response", string(response))
		} else {
			cbPublish(adapterConfig.TopicRoot+"/unknownAgent/response", string(response))
		}
	} else {
		log.Printf("[ERROR] sendResponse - Error marshalling JSON: %s\n", err.Error())
	}
}

// This function is responsible for returning an unsuccessful SNMP response to the invoking client
func sendErrorResponse(request snmpAdapterRequestType, error string) {
	response, err := json.Marshal(snmpAdapterResponseType{
		Request:  request,
		Success:  false,
		Error:    error,
		SnmpOIDs: make([]snmpJsonPDUType, 0),
	})

	if err == nil {
		if request.SnmpAgent != "" {
			cbPublish(adapterConfig.TopicRoot+"/"+request.SnmpAgent+"/error", string(response))
		} else {
			cbPublish(adapterConfig.TopicRoot+"/unknownAgent/error", string(response))
		}
	} else {
		log.Printf("[ERROR] sendErrorResponse - Error marshalling JSON: %s\n", err.Error())
	}
}

// This function is responsible for creating a SNMP trap server
func createTrapServer(agentName string, settings snmpAgentSettingsType) {
	var trapServer = snmp.NewTrapListener()
	trapServer.OnNewTrap = SnmpTrapHandler
	trapServer.Params = snmpAgents[agentName].(*snmp.GoSNMP)

	trapServers[agentName] = trapServer

	err := trapServer.Listen("0.0.0.0:" + strconv.Itoa(int(settings.TrapServerPort)))
	if err != nil {
		log.Printf("[ERROR] createTrapServer - Error encountered invoking trapServer.listen: %s\n", err)
	}
}

// This function is responsible for handling any received SNMP traps
func SnmpTrapHandler(packet *snmp.SnmpPacket, addr *net.UDPAddr) {
	log.Printf("[DEBUG] snmpTrapHandler - Received SNMP trap from %s\n", addr.IP)
	log.Printf("[DEBUG] snmpTrapHandler - Trap data received: %+v\n", packet)
	log.Printf("[DEBUG] snmpTrapHandler - addr data received: %+v\n", addr)

	agent := getAgentForTrap(addr.IP.String())

	//Publish trap data
	trapData := snmpTrapType{
		SnmpAgent: agent,
		Target:    addr.IP.String(),
		SnmpOIDs:  createJSONFromPDUs(packet.Variables),
	}

	fmt.Printf("[DEBUG] SnmpTrapHandler - Publishing trap data: %+v\n", trapData)
	if trapJSON, err := json.Marshal(trapData); err != nil {
		log.Printf("[ERROR] SnmpTrapHandler - Error marshalling JSON trap data: %s\n", err.Error())
	} else {
		if agent != "" {
			cbPublish(adapterConfig.TopicRoot+"/"+agent+"/trap", string(trapJSON))
		} else {
			log.Printf("[ERROR] SnmpTrapHandler - Agent with IP address %s does not exist. Cannot process SNMP trap", addr.IP.String())
		}
	}
}

func executeSnmpOperation(connection *snmp.GoSNMP, payload snmpAdapterRequestType) error {
	//Typically, SNMP uses UDP as its transport protocol.
	//The well known UDP ports for SNMP traffic are 161 (SNMP) and 162 (SNMPTRAP)
	// var Default = &GoSNMP{
	// 	Port:               161,
	// 	Transport:          "udp",
	// 	Community:          "public",
	// 	Version:            Version2c,
	// 	Timeout:            time.Duration(2) * time.Second,
	// 	Retries:            3,
	// 	ExponentialTimeout: true,
	// 	MaxOids:            MaxOids,
	// }
	log.Println("[DEBUG] executeSnmpOperation - Executing snmp operation")

	response := snmpAdapterResponseType{
		Request: payload,
	}
	var result interface{}
	var err error

	//	type Asn1BER byte

	// Asn1BER's - http://www.ietf.org/rfc/rfc1442.txt
	//	const (
	// EndOfContents     Asn1BER = 0x00
	// UnknownType       Asn1BER = 0x00
	// Boolean           Asn1BER = 0x01
	// Integer           Asn1BER = 0x02
	// BitString         Asn1BER = 0x03
	// OctetString       Asn1BER = 0x04
	// Null              Asn1BER = 0x05
	// ObjectIdentifier  Asn1BER = 0x06
	// ObjectDescription Asn1BER = 0x07
	// IPAddress         Asn1BER = 0x40
	// Counter32         Asn1BER = 0x41
	// Gauge32           Asn1BER = 0x42
	// TimeTicks         Asn1BER = 0x43
	// Opaque            Asn1BER = 0x44
	// NsapAddress       Asn1BER = 0x45
	// Counter64         Asn1BER = 0x46
	// Uinteger32        Asn1BER = 0x47
	// OpaqueFloat       Asn1BER = 0x78
	// OpaqueDouble      Asn1BER = 0x79
	// NoSuchObject      Asn1BER = 0x80
	// NoSuchInstance    Asn1BER = 0x81
	// EndOfMibView      Asn1BER = 0x82
	//	)

	operation := payload.SnmpOperation

	switch operation {
	case snmpGetOperation:
		result, err = connection.Get(getOidArrayFromJSON(payload.SnmpOIDs)) //returns (result *SnmpPacket, err error)
	case snmpGetNextOperation:
		result, err = connection.GetNext(getOidArrayFromJSON(payload.SnmpOIDs)) // returns (result *SnmpPacket, err error)
	case snmpGetBulk:
		result, err = connection.GetBulk(getOidArrayFromJSON(payload.SnmpOIDs), uint8(connection.NonRepeaters), connection.MaxRepetitions) // returns (result *SnmpPacket, err error)
	case snmpSetOperation:
		result, err = connection.Set(createPDUsFromJSON(payload.SnmpOIDs)) // returns (result *SnmpPacket, err error)
	case snmpWalkOperation:
		err = errors.New("SNMP walk currently not supported") // returns error
	case snmpWalkAllOperation:
		err = errors.New("SNMP walk all currently not supported") // returns (results []SnmpPDU, err error)
	case snmpBulkWalkOperation:
		err = errors.New("SNMP bulk walk currently not supported") // returns error
	case snmpBulkWalkAllOperation:
		err = errors.New("SNMP bulk walk all0c[] currently not supported") // returns (results []SnmpPDU, err error)
	default:
		err = errors.New("Invalid snmp operation: " + operation)
	}

	if err != nil {
		log.Printf("[ERROR] executeSnmpOperation - Error executing snmp operation: %s\n", err.Error())
		return err
	}

	//Create JSON response - Need to see if the results interface is []SnmpPDU or *SnmpPacket.
	switch v := result.(type) {
	case *snmp.SnmpPacket:
		//get, getnext, getbulk, set
		response.SnmpOIDs = createJSONFromPDUs(result.(*snmp.SnmpPacket).Variables)
	case []snmp.SnmpPDU:
		//walkall, bulkwalkall
		response.SnmpOIDs = createJSONFromPDUs(result.([]snmp.SnmpPDU))
	default:
		fmt.Printf("Unsupported type: %v", v)
	}

	log.Printf("[DEBUG] executeSnmpOperation - response: %+v\n", response)
	sendResponse(response)
	return nil
}

func createJSONFromPDUs(pdus []snmp.SnmpPDU) []snmpJsonPDUType {
	pduJSON := make([]snmpJsonPDUType, len(pdus))

	for ndx, pdu := range pdus {
		pduJSON[ndx] = snmpJsonPDUType{
			Name: pdu.Name,
			Type: int(pdu.Type),
		}

		// snmp.EndOfContents: // or snmp.UnknownType Asn1BER = 0x00, returned as nil by snmp library
		// snmp.Boolean: //Asn1BER = 0x01,
		// snmp.Integer: //Asn1BER = 0x02, Returned as int by snmp library
		// snmp.BitString: //Asn1BER = 0x03, Returned as int by snmp library
		// snmp.Null: //Asn1BER = 0x05, returned as nil by snmp library
		// snmp.ObjectIdentifier: //Asn1BER = 0x06, Returned as string by snmp library
		// snmp.ObjectDescription: //Asn1BER = 0x07,
		// snmp.IPAddress: //Asn1BER = 0x40, Returned as string by snmp library
		// snmp.Counter32: //Asn1BER = 0x41, Returned as Uint by snmp library
		// snmp.Gauge32: //Asn1BER = 0x42, Returned as Uint by snmp library
		// snmp.TimeTicks: //Asn1BER = 0x43, Returned as Uint32 by snmp library
		// snmp.Opaque: //Asn1BER = 0x44, Returned as byte[] by snmp library
		// snmp.NsapAddress: //Asn1BER = 0x45
		// snmp.Counter64: //Asn1BER = 0x46, Returned as Uint64 by snmp library
		// snmp.Uinteger32: //Asn1BER = 0x47, Returned as Uint32 by snmp library
		// snmp.OpaqueFloat: //Asn1BER = 0x78, Returned as float32 by snmp library
		// snmp.OpaqueDouble: //Asn1BER = 0x79, Returned as float64 by snmp library
		// snmp.NoSuchObject: //Asn1BER = 0x80, returned as nil by snmp library
		// snmp.NoSuchInstance: //Asn1BER = 0x81, returned as nil by snmp library
		// snmp.EndOfMibView: //Asn1BER = 0x82, returned as nil by snmp library
		// snmp.OctetString: //Asn1BER = 0x04, Returned as byte[] by snmp library
		switch pdu.Type {
		case snmp.OctetString, snmp.Opaque: //Asn1BER = 0x04, Returned as byte[] by snmp library
			pduJSON[ndx].Value = string(pdu.Value.([]byte))
		default:
			pduJSON[ndx].Value = pdu.Value
		}
	}

	return pduJSON
}

func createPDUsFromJSON(jsonPdus []snmpJsonPDUType) []snmp.SnmpPDU {
	pdus := make([]snmp.SnmpPDU, len(jsonPdus))

	for ndx, pdu := range jsonPdus {
		pdus[ndx] = snmp.SnmpPDU{
			Name: pdu.Name,
			Type: snmp.Asn1BER(pdu.Type),
		}

		// snmp.EndOfContents: // or snmp.UnknownType Asn1BER = 0x00
		// snmp.Boolean: //Asn1BER = 0x01,
		// snmp.Integer: //Asn1BER = 0x02, Passed as int type
		// snmp.BitString: //Asn1BER = 0x03, Passed as byte[]
		// snmp.Null: //Asn1BER = 0x05
		// snmp.ObjectIdentifier: //Asn1BER = 0x06, Passed as string
		// snmp.ObjectDescription: //Asn1BER = 0x07, Passed as string
		// snmp.IPAddress: //Asn1BER = 0x40, Passed as string
		// snmp.Counter32: //Asn1BER = 0x41, Passed as Uint32
		// snmp.Gauge32: //Asn1BER = 0x42, Passed as Uint32
		// snmp.TimeTicks: //Asn1BER = 0x43, Passed as Uint32
		// snmp.Opaque: //Asn1BER = 0x44, Passed as byte[]
		// snmp.NsapAddress: //Asn1BER = 0x45
		// snmp.Counter64: //Asn1BER = 0x46, Passed as Uint64??
		// snmp.Uinteger32: //Asn1BER = 0x47, Passed as Uint32
		// snmp.OpaqueFloat: //Asn1BER = 0x78, Returned as float32 by snmp library
		// snmp.OpaqueDouble: //Asn1BER = 0x79, Returned as float64 by snmp library
		// snmp.NoSuchObject: //Asn1BER = 0x80, returned as nil by snmp library
		// snmp.NoSuchInstance: //Asn1BER = 0x81, returned as nil by snmp library
		// snmp.EndOfMibView: //Asn1BER = 0x82, returned as nil by snmp library
		// snmp.OctetString: //Asn1BER = 0x04, Passed as byte[]
		switch snmp.Asn1BER(pdu.Type) {
		//TODO: Determine if it's even possible to send these values to a SNMP server
		// case snmp.EndOfContents, snmp.Null, snmp.NoSuchObject, snmp.NoSuchInstance, snmp.EndOfMibView:
		// 	pdus[ndx].Value = pdu.Value.(int)
		case snmp.Integer:
			pdus[ndx].Value = pdu.Value.(int)
		case snmp.Counter32, snmp.Gauge32, snmp.TimeTicks, snmp.Uinteger32:
			pdus[ndx].Value = pdu.Value.(uint32)
		case snmp.Counter64:
			pdus[ndx].Value = pdu.Value.(uint64)
		case snmp.OpaqueFloat:
			pdus[ndx].Value = pdu.Value.(float32)
		case snmp.OpaqueDouble:
			pdus[ndx].Value = pdu.Value.(float64)
		case snmp.OctetString, snmp.BitString, snmp.Opaque:
			pdus[ndx].Value = pdu.Value.([]byte)
		default:
			pdus[ndx].Value = pdu.Value
		}
	}

	return pdus
}

func getOidArrayFromJSON(jsonPdus []snmpJsonPDUType) []string {
	oids := make([]string, len(jsonPdus))

	for ndx, jsonPdu := range jsonPdus {
		oids[ndx] = jsonPdu.Name
	}

	return oids
}

func convertSnmpVersion(versionNum uint8) snmp.SnmpVersion {
	switch versionNum {
	case 1:
		return snmp.Version1
	case 2:
		return snmp.Version2c
	case 3:
		return snmp.Version3
	default:
		return snmp.Version2c
	}
}

func cleanUpAgentsAndTrapServers(newSettings snmpAgentMapType) {
	for key, _ := range adapterSettings {
		//See if an agent that existed in the previous adapter settings has been removed
		//from the new settings
		if _, ok := newSettings[key]; !ok {
			//If a trap server exists for the old agent, close it and remove it
			if trapServerExists(key) {
				log.Printf("[DEBUG] Deleting trap server for agent %s\n", key)
				trapServers[key].(*snmp.TrapListener).Close()
				delete(trapServers, key)
			}
			//Remove the agent
			delete(snmpAgents, key)
		}
	}
}

// Validates the agent settings in the adapter config collection
func agentSettingsAreValid(settings snmpAgentSettingsType) (bool, error) {
	//Target is required
	if settings.Target == "" {
		return false, fmt.Errorf("target is empty")
	}

	if settings.ShouldHandleTraps && settings.TrapServerPort == 0 {
		log.Println("[DEBUG] NonRepeaters has changed, returning true")
		return false, fmt.Errorf("trap server port not provided")
	}

	//Port - not required, will default to 161 in snmp.Default
	//Transport - not required, will default to "udp" in snmp.Default
	//Community - not required, will default to "public" in snmp.Default
	//Version - not required, will default to Version2c in snmp.Default
	//Timeout - not required, will default to 2 seconds in snmp.Default
	//Retries - not required, will default to 3 in snmp.Default
	//ExponentialTimeout - not required, will default to true in snmp.Default
	//MaxOids - not required, will default to MaxOids in snmp.Default
	//MaxRepetitions - not required, will default to defaultMaxRepetitions in snmp.Default
	//NonRepeaters - not required, will default to 0 in snmp.Default
	//UseUnconnectedUDPSocket - not required, will default to false in snmp.Default
	//AppOpts map[string]interface{} - option "c" is the only option currently supported by gosnmp
	if settings.SnmpAppOpts != nil && settings.SnmpAppOpts["c"] != nil && reflect.TypeOf(settings.SnmpAppOpts["c"]).Kind() != reflect.Bool {
		return false, fmt.Errorf("boolean value not passec for SnmpAppOpts option c")
	}

	//TODO: Add validations for the SNMP V3 fields. Not sure which of these can be passed in or which ones
	// are generated automatically
	//
	//if settings.SnmpVersion == uint8(snmp.Version3) {
	//MsgFlags SnmpV3MsgFlags
	//SecurityModel SnmpV3SecurityModel
	//SecurityParameters SnmpV3SecurityParameters
	//ContextEngineID - not required, will default
	//ContextName string
	//}
	return true, nil
}

func agentSettingsHaveChanged(agentName string, oldSettings snmpAgentSettingsType, newSettings snmpAgentSettingsType) bool {
	return !reflect.DeepEqual(oldSettings, newSettings)
}

func agentExists(agentName string) bool {
	return attributeExistsInMap(agentName, snmpAgents)
}

func trapServerExists(agentName string) bool {
	return attributeExistsInMap(agentName, trapServers)
}

func attributeExistsInMap(attrName string, theMap map[string]interface{}) bool {
	if _, ok := theMap[attrName]; ok {
		return true
	}
	return false
}

func getAgentForTrap(trapIp string) string {
	log.Printf("[DEBUG] Finding agent name for IP %s", trapIp)
	for agentName, agent := range snmpAgents {
		if agent.(*gosnmp.GoSNMP).Target == trapIp {
			return agentName
		}
	}
	return ""
}
