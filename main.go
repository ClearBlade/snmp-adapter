package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	adapter_library "github.com/clearblade/adapter-go-library"
	"github.com/clearblade/mqtt_parsing"
	mqttTypes "github.com/clearblade/mqtt_parsing"
	"github.com/gosnmp/gosnmp"
	snmp "github.com/gosnmp/gosnmp"
)

type snmpAdapterSettingsType struct {
	ShouldHandleTraps      bool   `json:"shouldHandleTraps"`
	Port                   uint16 `json:"trapServerPort"`
	SnmpConnectionSettings snmpConnectionSettingsType
}

type snmpConnectionSettingsType struct {
	//Transport protocol to use ("udp" or "tcp"); if unset "udp" will be used.
	SnmpTransport string `json:"snmpTransport"`

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
	// SnmpMaxRepetitions uint8 `json:"snmpMaxRepetitions"`
	// DWB changed to avoid type mismatch -- maybe caused by new SNMP library?
	SnmpMaxRepetitions uint32 `json:"snmpMaxRepetitions"`

	// NonRepeaters sets the GETBULK max-repeaters used by BulkWalk*
	// (default: 0 as per RFC 1905)
	SnmpNonRepeaters int `json:"snmpNonRepeaters"`

	// netsnmp has '-C APPOPTS - set various application specific behaviours'
	//
	// - 'c: do not check returned OIDs are increasing' - use AppOpts = map[string]interface{"c":true} with
	//   Walk() or BulkWalk(). The library user needs to implement their own policy for terminating walks.
	// - 'p,i,I,t,E' -> pull requests welcome
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
	Target string `json:"snmpAddress"`
	Port   uint16 `json:"snmpPort"`
	// SnmpOIDs is a slice of type string []string `json:"snmpOIDs"`
	SnmpOIDs []snmpJsonPDUType `json:"snmpOIDs"`

	//The SNMP operation to invoke.
	//One of get, getnext, getbulk, set, walk, walkall, bulkwalk, bulkwalkall
	SnmpOperation string `json:"snmpOperation"`

	snmpConnectionSettings snmpConnectionSettingsType
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

type snmpAdapterResponseType struct {
	Request  snmpAdapterRequestType `json:"request"`
	Success  bool                   `json:"success"`
	Error    string                 `json:"error"`
	SnmpOIDs []snmpJsonPDUType      `json:"snmpOIDs"`
}

const (
	platURL                        = "http://localhost:9000"
	messURL                        = "localhost:1883"
	msgSubscribeQos                = 0
	msgPublishQos                  = 0
	defaultTopicRoot               = "snmp"
	adapterConfigCollectionDefault = "adapter_config"
	defaultSnmpTargetPort          = 161
	defaultTrapServerPort          = 162
	defaultSnmpTimeout             = time.Duration(2) * time.Second
	snmpGetOperation               = "get"
	snmpGetNextOperation           = "getnext"
	snmpGetBulk                    = "getbulk"
	snmpSetOperation               = "set"
	snmpGetResponseOperation       = "getresponse"  //TODO:Not implemented, sent by SNMP agents
	snmpTrapOperation              = "trap"         //TODO:Not implemented, sent by SNMP agents
	snmpNotificationOperation      = "notification" //TODO:Not implemented, sent by SNMP agents
	snmpInformOperation            = "inform"       //TODO:Not implemented, sent by SNMP agents
	snmpReportOperation            = "report"       //TODO:Not implemented, SNMP v3 only
	snmpWalkOperation              = "walk"         //TODO:
	snmpWalkAllOperation           = "walkall"      //TODO:
	snmpBulkWalkOperation          = "bulkwalk"     //TODO:
	snmpBulkWalkAllOperation       = "bulkwalkall"  //TODO:
)

var (
	//Adapter command line arguments
	adapterName     = "snmp-adapter"
	logLevel        string //Defaults to info
	adapterConfig   *adapter_library.AdapterConfig
	adapterSettings snmpAdapterSettingsType

	//SNMP specific variables
	trapServer *snmp.TrapListener
)

func main() {
	fmt.Println("Starting snmpAdapter...")

	err := adapter_library.ParseArguments(adapterName)
	if err != nil {
		log.Fatalf("[FATAL] Failed to parse arguments: %s\n", err.Error())
	}

	adapterConfig, err = adapter_library.Initialize()
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize: %s\n", err.Error())
	}

	err = json.Unmarshal([]byte(adapterConfig.AdapterSettings), &adapterSettings)
	if err != nil {
		log.Fatalf("[FATAL] Failed to parse Adapter Settings: %s\n", err.Error())
	}

	//Connect to the MQTT broker and subscribe to the request topic
	err = adapter_library.ConnectMQTT(adapterConfig.TopicRoot+"/request", cbMessageHandler)
	if err != nil {
		log.Fatalf("[FATAL] Failed to connect MQTT: %s\n", err.Error())
	}

	if adapterSettings.ShouldHandleTraps == true {
		log.Printf("[INFO] applyAdapterConfig - Starting trap server on port %d\n", adapterSettings.Port)
		go createTrapServer()
	}

	// wait for signal to stop/kill process to allow for graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	sig := <-c

	log.Printf("[INFO] OS signal %s received, gracefully shutting down adapter.\n", sig)
	//Close
	if trapServer != nil {
		trapServer.Close()
	}

	os.Exit(0)
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
func handleRequest(topic mqtt_parsing.TopicPath, jsonPayload snmpAdapterRequestType) {
	if connection, err := getSnmpConnection(jsonPayload); err != nil {
		sendErrorResponse(jsonPayload, "Error creating SNMP Connection: "+err.Error())
	} else {
		if err := executeSnmpOperation(connection, jsonPayload); err != nil {
			sendErrorResponse(jsonPayload, err.Error())
		}
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
func getSnmpConnection(payload snmpAdapterRequestType) (*snmp.GoSNMP, error) {
	log.Println("[DEBUG] getConnection - Verifying connection parameters")

	if payload.Target == "" {
		log.Printf("[ERROR] getConnection - snmpAddress not specified in incoming payload: %+v\n", payload)
		return nil, errors.New("snmpAddress not specified in incoming payload")
	}

	//TODO: May need to make this required for only SNMP V1
	if payload.snmpConnectionSettings.SnmpCommunity == "" {
		log.Printf("[ERROR] getConnection - snmpCommunity not specified in incoming payload: %+v\n", payload)
		return nil, errors.New("snmpCommunity not specified in incoming payload")
	}

	if payload.snmpConnectionSettings.SnmpVersion == 0 {
		log.Printf("[ERROR] getConnection - snmpVersion not specified in incoming payload: %+v\n", payload)
		return nil, errors.New("snmpVersion not specified in incoming payload")
	}

	params := &snmp.GoSNMP{
		Target:             payload.Target,
		Port:               payload.Port,
		Community:          payload.snmpConnectionSettings.SnmpCommunity,
		Timeout:            time.Duration(payload.snmpConnectionSettings.SnmpTimeout) * time.Second,
		Version:            convertSnmpVersion(payload.snmpConnectionSettings.SnmpVersion),
		Retries:            payload.snmpConnectionSettings.SnmpRetries,
		ExponentialTimeout: payload.snmpConnectionSettings.SnmpExponentialTimeout,
		MaxOids:            payload.snmpConnectionSettings.SnmpMaxOids,
		MaxRepetitions:     payload.snmpConnectionSettings.SnmpMaxRepetitions,
		NonRepeaters:       payload.snmpConnectionSettings.SnmpNonRepeaters,
		AppOpts:            payload.snmpConnectionSettings.SnmpAppOpts,
		ContextEngineID:    payload.snmpConnectionSettings.SnmpContextEngineID,
		ContextName:        payload.snmpConnectionSettings.SnmpContextName,
	}

	log.Printf("[DEBUG] getConnection - SNMP version set to %+v\n", params.Version)

	if payload.Port == 0 {
		params.Port = defaultSnmpTargetPort
	}

	if payload.snmpConnectionSettings.SnmpTransport == "tcp" ||
		payload.snmpConnectionSettings.SnmpTransport == "udp" {
		params.Transport = payload.snmpConnectionSettings.SnmpTransport
	} else {
		//Defaulting occurs in validateParameters method of GoSNMP
		log.Println("[DEBUG] getConnection - Transport defaulted to udp")
	}

	if payload.snmpConnectionSettings.SnmpTimeout == 0 {
		params.Timeout = defaultSnmpTimeout
	}

	//TODO: Implement when needed
	//
	//if params.Version == snmp.Version3 {
	// MsgFlags:           payload.snmpConnectionSettings.SnmpMsgFlags,
	// SecurityModel:      payload.snmpConnectionSettings.SnmpSecurityModel,
	// SecurityParameters: payload.snmpConnectionSettings.SnmpSecurityParameters,
	//}

	if logLevel == "debug" {
		gosnmp.Default.Logger = snmp.NewLogger(log.New(os.Stdout, "", 0))
	}

	return params, params.Connect()
}

// This function is responsible for returning a successful SNMP response to the invoking client
func sendResponse(returnData snmpAdapterResponseType) {
	response, err := json.Marshal(returnData)

	if err == nil {
		cbPublish(adapterConfig.TopicRoot+"/response", string(response))
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
		cbPublish(adapterConfig.TopicRoot+"/error", string(response))
	} else {
		log.Printf("[ERROR] sendErrorResponse - Error marshalling JSON: %s\n", err.Error())
	}
}

// This function is responsible for creating a SNMP trap server
func createTrapServer() {
	trapServer = snmp.NewTrapListener()
	trapServer.OnNewTrap = SnmpTrapHandler

	//TODO: Determine which of these we can get rid of
	trapServer.Params = &snmp.GoSNMP{
		Port:               adapterSettings.Port,
		Community:          adapterSettings.SnmpConnectionSettings.SnmpCommunity,
		Timeout:            time.Duration(adapterSettings.SnmpConnectionSettings.SnmpTimeout) * time.Second,
		Version:            convertSnmpVersion(adapterSettings.SnmpConnectionSettings.SnmpVersion),
		Retries:            adapterSettings.SnmpConnectionSettings.SnmpRetries,
		ExponentialTimeout: adapterSettings.SnmpConnectionSettings.SnmpExponentialTimeout,
		MaxOids:            adapterSettings.SnmpConnectionSettings.SnmpMaxOids,
		MaxRepetitions:     adapterSettings.SnmpConnectionSettings.SnmpMaxRepetitions,
		NonRepeaters:       adapterSettings.SnmpConnectionSettings.SnmpNonRepeaters,
		AppOpts:            adapterSettings.SnmpConnectionSettings.SnmpAppOpts,
		ContextEngineID:    adapterSettings.SnmpConnectionSettings.SnmpContextEngineID,
		ContextName:        adapterSettings.SnmpConnectionSettings.SnmpContextName,
	}

	if logLevel == "debug" {
		trapServer.Params.Logger = gosnmp.NewLogger(log.New(os.Stdout, "", 0))
	}

	err := trapServer.Listen("0.0.0.0:" + strconv.Itoa(int(adapterSettings.Port)))
	if err != nil {
		log.Printf("[ERROR] createTrapServer - Error encountered invoking trapServer.listen: %s\n", err)
		log.Panicf("Error encountered invoking trapServer.listen: %s\n", err)
	}
}

// This function is responsible for handling any received SNMP traps
func SnmpTrapHandler(packet *snmp.SnmpPacket, addr *net.UDPAddr) {
	log.Printf("[DEBUG] snmpTrapHandler - Received SNMP trap from %s\n", addr.IP)
	log.Printf("[DEBUG] snmpTrapHandler - Trap data received: %+v\n", packet.Variables)

	//Publish trap data
	var trapData []snmpJsonPDUType = createJSONFromPDUs(packet.Variables)
	fmt.Printf("[DEBUG] formatTrap - Publishing trap data: %+v\n", trapData)
	if trapJSON, err := json.Marshal(trapData); err != nil {
		log.Printf("[ERROR] formatTrap - Error marshalling JSON trap data: %s\n", err.Error())
	} else {
		cbPublish(adapterConfig.TopicRoot+"/trap", string(trapJSON))
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
			pduJSON[ndx].Value = pdu.Value.([]byte)
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
		return snmp.Version3
	}
}
