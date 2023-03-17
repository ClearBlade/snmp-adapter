package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	cb "github.com/clearblade/Go-SDK"
	mqttTypes "github.com/clearblade/mqtt_parsing"
	mqtt "github.com/clearblade/paho.mqtt.golang"
	"github.com/hashicorp/logutils"

	// snmp "github.com/soniah/gosnmp"
	// DEPRECATED
	// DWB changed to point to new Github repo for gosnmp code
	// "github.com/gosnmp/gosnmp"

	"github.com/gosnmp/gosnmp"
	snmp "github.com/gosnmp/gosnmp"
)

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
	snmpGetResponseOperation       = "getresponse"  //Not implemented, sent by SNMP agents
	snmpTrapOperation              = "trap"         //Not implemented, sent by SNMP agents
	snmpNotificationOperation      = "notification" //Not implemented, sent by SNMP agents
	snmpInformOperation            = "inform"       //Not implemented, sent by SNMP agents
	snmpReportOperation            = "report"       //Not implemented, SNMP v3 only
	snmpWalkOperation              = "walk"         //TODO
	snmpWalkAllOperation           = "walkall"      //TODO
	snmpBulkWalkOperation          = "bulkwalk"     //TODO
	snmpBulkWalkAllOperation       = "bulkwalkall"  //TODO
)

var (
	//Adapter command line arguments
	platformURL             string //Defaults to http://localhost:9000
	messagingURL            string //Defaults to localhost:1883
	sysKey                  string
	sysSec                  string
	deviceName              string //Defaults to snmpAdapter
	activeKey               string
	logLevel                string //Defaults to info
	adapterConfigCollection string

	//SNMP specific variables
	trapServer *snmp.TrapListener

	//Miscellaneous adapter variables
	cbBroker           cbPlatformBroker
	cbSubscribeChannel <-chan *mqttTypes.Publish
	endWorkersChannel  chan string
	interruptChannel   chan os.Signal
	config             adapterConfig
)

type adapterConfig struct {
	adapterSettings
	TopicRoot string `json:"topic_root"`
}

type adapterSettings struct {
	ShouldHandleTraps bool   `json:"shouldHandleTraps"`
	Port              uint16 `json:"trapServerPort"`
	snmpConnectionSettings
}

type snmpConnectionSettings struct {
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

	// MsgFlags is an SNMPV3 MsgFlags - describe Authentication, Privacy, and whether a report PDU must be sent
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

type adapterRequest struct {
	Target string `json:"snmpAddress"`
	Port   uint16 `json:"snmpPort"`
	// SnmpOIDs is a slice of type string []string `json:"snmpOIDs"`
	SnmpOIDs []string `json:"snmpOIDs"`

	// DB added code to create values for the setType and setValue key:values
	// These will only be available in the IA Control messages
	// Type only works is hard coded as Integer: ANS1BER = 2 for now
	SnmpSetType  int    `json:"setType"`
	SnmpSetValue uint16 `json:"setValue"`

	//The SNMP operation to invoke.
	//One of get, getnext, getbulk, set, walk, walkall, bulkwalk, bulkwalkall
	SnmpOperation string `json:"snmpOperation"`

	snmpConnectionSettings
}

type cbPlatformBroker struct {
	name         string
	clientID     string
	client       *cb.DeviceClient
	platformURL  *string
	messagingURL *string
	systemKey    *string
	systemSecret *string
	deviceName   *string
	password     *string
	topic        string
	qos          int
}

func init() {
	flag.StringVar(&sysKey, "systemKey", "", "system key (required)")
	flag.StringVar(&sysSec, "systemSecret", "", "system secret (required)")
	flag.StringVar(&deviceName, "deviceName", "snmpAdapter", "name of device (optional)")
	flag.StringVar(&activeKey, "password", "", "password (or active key) for device authentication (required)")
	flag.StringVar(&platformURL, "platformURL", platURL, "platform url (optional)")
	flag.StringVar(&messagingURL, "messagingURL", messURL, "messaging URL (optional)")
	flag.StringVar(&logLevel, "logLevel", "info", "The level of logging to use. Available levels are 'debug, 'info', 'warn', 'error', 'fatal' (optional)")
	flag.StringVar(&adapterConfigCollection, "adapterConfigCollection", adapterConfigCollectionDefault, "The name of the data collection used to house adapter configuration (optional)")
}

func usage() {
	log.Printf("Usage: snmpAdapter [options]\n\n")
	flag.PrintDefaults()
}

func validateFlags() {
	flag.Parse()

	if sysKey == "" || sysSec == "" || activeKey == "" {

		log.Printf("ERROR - Missing required flags\n\n")
		flag.Usage()
		os.Exit(1)
	}
}

func main() {
	fmt.Println("Starting snmpAdapter...")

	//Validate the command line flags
	flag.Usage = usage
	validateFlags()

	rand.Seed(time.Now().UnixNano())

	//Initialize the logging mechanism
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	filter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "INFO", "WARN", "ERROR", "FATAL"},
		MinLevel: logutils.LogLevel(strings.ToUpper(logLevel)),
		Writer:   os.Stdout,
	}

	log.SetOutput(filter)

	//Add mqtt logging
	// logger := log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile)
	// mqtt.ERROR = logger
	// mqtt.CRITICAL = logger
	// mqtt.WARN = logger
	// mqtt.DEBUG = logger

	cbBroker = cbPlatformBroker{
		name:         "ClearBlade",
		clientID:     deviceName + "_client",
		client:       nil,
		platformURL:  &platformURL,
		messagingURL: &messagingURL,
		systemKey:    &sysKey,
		systemSecret: &sysSec,
		deviceName:   &deviceName,
		password:     &activeKey,
		topic:        "",
		qos:          msgSubscribeQos,
	}

	// Initialize ClearBlade Client
	if err := initCbClient(cbBroker); err != nil {
		log.Println(err.Error())
		log.Println("Unable to initialize CB broker client. Exiting.")
		return
	}

	defer close(endWorkersChannel)
	endWorkersChannel = make(chan string)

	//Handle OS interrupts to shut down gracefully
	interruptChannel := make(chan os.Signal, 1)
	signal.Notify(interruptChannel, syscall.SIGINT, syscall.SIGTERM)
	sig := <-interruptChannel

	log.Printf("[INFO] OS signal %s received, ending go routines.", sig)

	//End the existing goRoutines
	endWorkersChannel <- "Stop Channel"

	//Close
	if trapServer != nil {
		trapServer.Close()
	}
	os.Exit(0)
}

// ClearBlade Client init helper
func initCbClient(platformBroker cbPlatformBroker) error {
	log.Println("[INFO] initCbClient - Initializing the ClearBlade client")

	log.Printf("[DEBUG] initCbClient - Platform URL: %s\n", *(platformBroker.platformURL))
	log.Printf("[DEBUG] initCbClient - Platform Messaging URL: %s\n", *(platformBroker.messagingURL))
	log.Printf("[DEBUG] initCbClient - System Key: %s\n", *(platformBroker.systemKey))
	log.Printf("[DEBUG] initCbClient - System Secret: %s\n", *(platformBroker.systemSecret))
	log.Printf("[DEBUG] initCbClient - Device Name: %s\n", *(platformBroker.deviceName))
	log.Printf("[DEBUG] initCbClient - Password: %s\n", *(platformBroker.password))

	cbBroker.client = cb.NewDeviceClientWithAddrs(*(platformBroker.platformURL), *(platformBroker.messagingURL), *(platformBroker.systemKey), *(platformBroker.systemSecret), *(platformBroker.deviceName), *(platformBroker.password))

	for err := cbBroker.client.Authenticate(); err != nil; {
		log.Printf("[ERROR] initCbClient - Error authenticating %s: %s\n", platformBroker.name, err.Error())
		log.Println("[ERROR] initCbClient - Will retry in 1 minute...")

		// sleep 1 minute
		time.Sleep(time.Duration(time.Minute * 1))
		err = cbBroker.client.Authenticate()
	}

	//Retrieve adapter configuration data
	log.Println("[INFO] initCbClient - Retrieving adapter configuration...")
	getAdapterConfig()

	log.Println("[INFO] initCbClient - Initializing MQTT")
	callbacks := cb.Callbacks{OnConnectionLostCallback: onConnectLost, OnConnectCallback: onConnect}
	if err := cbBroker.client.InitializeMQTTWithCallback(platformBroker.clientID+"-"+strconv.Itoa(rand.Intn(10000)), "", 30, nil, nil, &callbacks); err != nil {
		log.Fatalf("[FATAL] initCbClient - Unable to initialize MQTT connection with %s: %s", platformBroker.name, err.Error())
		return err
	}

	return nil
}

// If the connection to the broker is lost, we need to reconnect and
// re-establish all of the subscriptions
func onConnectLost(client mqtt.Client, connerr error) {
	log.Printf("[INFO] OnConnectLost - Connection to broker was lost: %s\n", connerr.Error())

	//End the existing goRoutines
	endWorkersChannel <- "Stop Channel"

	if trapServer != nil {
		trapServer.Close()
	}

	//We don't need to worry about manally re-initializing the mqtt client. The auto reconnect logic will
	//automatically try and reconnect. The reconnect interval could be as much as 20 minutes.

	//Auto reconnect does not appear to be working in all cases. Let's just end and let the OS restart the adapter
	// log.Printf("[INFO] OnConnectLost - Sending SIGINT: \n")
	// interruptChannel <- syscall.SIGINT
}

// When the connection to the broker is complete, set up any subscriptions
// and authenticate the google pubsub client
func onConnect(client mqtt.Client) {
	log.Println("[INFO] OnConnect - Connected to ClearBlade Platform MQTT broker")

	//CleanSession, by default, is set to true. This results in non-durable subscriptions.
	//We therefore need to re-subscribe
	log.Println("[INFO] OnConnect - Begin configuring platform subscription")

	var err error
	for cbSubscribeChannel, err = cbSubscribe(config.TopicRoot + "/request"); err != nil; {
		//Wait 30 seconds and retry
		log.Printf("[ERROR] OnConnect - Error subscribing to MQTT: %s\n", err.Error())
		log.Println("[ERROR] OnConnect - Will retry in 30 seconds...")
		time.Sleep(time.Duration(30 * time.Second))
		cbSubscribeChannel, err = cbSubscribe(config.TopicRoot + "/request")
	}

	//Start subscribe worker
	go cbSubscribeWorker()
}

func cbSubscribeWorker() {
	log.Println("[INFO] subscribeWorker - Starting MQTT subscribeWorker")

	//Wait for subscriptions to be received
	for {
		select {
		case message, ok := <-cbSubscribeChannel:
			if ok {
				jsonPayload := adapterRequest{}
				if err := json.Unmarshal(message.Payload, &jsonPayload); err != nil {
					log.Printf("[ERROR] cbSubscribeWorker - Error encountered unmarshalling json: %s\n", err.Error())
					sendErrorResponse(message.Payload, err.Error())
				} else {
					log.Printf("[DEBUG] cbSubscribeWorker - Json payload received: %#v\n", jsonPayload)
					if connection, err := getConnection(jsonPayload); err != nil {
						sendErrorResponse(message.Payload, "Error creating SNMP Connection: "+err.Error())
					} else {
						if err := executeSnmpOperation(connection, jsonPayload); err != nil {
							sendErrorResponse(message.Payload, err.Error())
						}
					}
				}
			}
		case _ = <-endWorkersChannel:
			//End the current go routine when the stop signal is received
			log.Println("[INFO] subscribeWorker - Stopping subscribeWorker")
			return
		}
	}
}

// Subscribes to a topic
func cbSubscribe(topic string) (<-chan *mqttTypes.Publish, error) {
	log.Printf("[INFO] subscribe - Subscribing to MQTT topic %s\n", topic)
	subscription, error := cbBroker.client.Subscribe(topic, cbBroker.qos)
	if error != nil {
		log.Printf("[ERROR] subscribe - Unable to subscribe to MQTT topic: %s due to error: %s\n", topic, error.Error())
		return nil, error
	}

	log.Printf("[DEBUG] subscribe - Successfully subscribed to MQTT topic %s\n", topic)
	return subscription, nil
}

// Publishes data to a topic
func cbPublish(topic string, data string) error {
	log.Printf("[INFO] cbPublish - Publishing to topic %s\n", topic)
	error := cbBroker.client.Publish(topic, []byte(data), cbBroker.qos)
	if error != nil {
		log.Printf("[ERROR] cbPublish - Unable to publish to topic: %s due to error: %s\n", topic, error.Error())
		return error
	}

	log.Printf("[DEBUG] publish - Successfully published message to topic %s\n", topic)
	return nil
}

func getAdapterConfig() {
	log.Println("[INFO] getAdapterConfig - Retrieving adapter config")
	config = adapterConfig{
		TopicRoot: defaultTopicRoot,
	}

	//Retrieve the adapter configuration row
	query := cb.NewQuery()
	query.EqualTo("adapter_name", deviceName)

	//A nil query results in all rows being returned
	log.Println("[DEBUG] getAdapterConfig - Executing query against table " + adapterConfigCollection)
	results, err := cbBroker.client.GetDataByName(adapterConfigCollection, query)
	if err != nil {
		log.Println("[DEBUG] getAdapterConfig - Adapter configuration could not be retrieved. Using defaults")
		log.Printf("[ERROR] getAdapterConfig - Error retrieving adapter configuration: %s\n", err.Error())
	} else {
		data := results["DATA"].([]interface{})
		if len(data) > 0 {
			log.Println("[INFO] getAdapterConfig - Adapter config retrieved")
			configData := data[0].(map[string]interface{})

			//MQTT topic root
			if configData["topic_root"] != nil {
				config.TopicRoot = configData["topic_root"].(string)
			}
			log.Printf("[DEBUG] getAdapterConfig - TopicRoot set to %s\n", config.TopicRoot)

			//adapter_settings
			if configData["adapter_settings"] != nil {
				if err := json.Unmarshal([]byte(configData["adapter_settings"].(string)), &config); err != nil {
					log.Printf("[ERROR] getAdapterConfig - Error while unmarshalling adapter settings: %s. Defaulting all adapter settings.\n", err.Error())
					config.Port = 162
				}
			} else {
				log.Println("[INFO] applyAdapterConfig - Settings are nil. Defaulting all adapter settings.")
			}
		} else {
			log.Println("[INFO] getAdapterConfig - No rows returned. Using defaults")
		}
	}

	applyAdapterSettings(&config)
}

func applyAdapterSettings(config *adapterConfig) {
	if config.ShouldHandleTraps == true {
		log.Printf("[INFO] applyAdapterConfig - Starting trap server on port %d\n", config.Port)
		go createTrapServer(config)
	}
}

func getConnection(payload adapterRequest) (*snmp.GoSNMP, error) {
	log.Println("[DEBUG] getConnection - Verifying connection parameters")

	if payload.Target == "" {
		log.Printf("[ERROR] getConnection - snmpAddress not specified in incoming payload: %+v\n", payload)
		return nil, errors.New("snmpAddress not specified in incoming payload")
	}

	//TODO - May need to make this required for only SNMP V1
	if payload.SnmpCommunity == "" {
		log.Printf("[ERROR] getConnection - snmpCommunity not specified in incoming payload: %+v\n", payload)
		return nil, errors.New("snmpCommunity not specified in incoming payload")
	}

	if payload.SnmpVersion == 0 {
		log.Printf("[ERROR] getConnection - snmpVersion not specified in incoming payload: %+v\n", payload)
		return nil, errors.New("snmpVersion not specified in incoming payload")
	}

	params := &snmp.GoSNMP{
		Target:             payload.Target,
		Port:               payload.Port,
		Community:          payload.SnmpCommunity,
		Timeout:            time.Duration(payload.SnmpTimeout) * time.Second,
		Version:            convertSnmpVersion(payload.SnmpVersion),
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

	if payload.snmpConnectionSettings.SnmpTransport != "" && (payload.snmpConnectionSettings.SnmpTransport == "tcp" ||
		payload.snmpConnectionSettings.SnmpTransport == "udp") {
		params.Transport = payload.snmpConnectionSettings.SnmpTransport
	} else {
		//Defaulting occurs in validateParameters method of GoSNMP
		log.Println("[DEBUG] getConnection - Transport defaulted to udp")
	}

	if payload.snmpConnectionSettings.SnmpTimeout == 0 {
		params.Timeout = defaultSnmpTimeout
	}

	// MsgFlags:           payload.snmpConnectionSettings.SnmpMsgFlags,
	// SecurityModel:      payload.snmpConnectionSettings.SnmpSecurityModel,
	// SecurityParameters: payload.snmpConnectionSettings.SnmpSecurityParameters,

	if logLevel == "debug" {
		gosnmp.Default.Logger = gosnmp.NewLogger(log.New(os.Stdout, "", 0))
		// DWB changed to NewLogger as per SNMP library update
	}

	return params, params.Connect()
}

func sendResponse(returnData map[string]interface{}) {
	response, err := json.Marshal(returnData)

	if err == nil {
		cbPublish(config.TopicRoot+"/response", string(response))
	} else {
		log.Printf("[ERROR] sendResponse - Error marshalling JSON: %s\n", err.Error())
	}
}

func sendErrorResponse(request []byte, error string) {
	response, err := json.Marshal(map[string]interface{}{
		"request": request,
		"error":   error,
	})

	if err == nil {
		cbPublish(config.TopicRoot+"/error", string(response))
	} else {
		log.Printf("[ERROR] sendErrorResponse - Error marshalling JSON: %s\n", err.Error())
	}
}

func createTrapServer(config *adapterConfig) {
	trapServer = snmp.NewTrapListener()
	trapServer.OnNewTrap = snmpTrapHandler

	//TODO - Determine which of these we can get rid of
	trapServer.Params = &snmp.GoSNMP{
		Port:               config.Port,
		Community:          config.SnmpCommunity,
		Timeout:            time.Duration(config.SnmpTimeout) * time.Second,
		Version:            convertSnmpVersion(config.SnmpVersion),
		Retries:            config.SnmpRetries,
		ExponentialTimeout: config.SnmpExponentialTimeout,
		MaxOids:            config.SnmpMaxOids,
		MaxRepetitions:     config.SnmpMaxRepetitions,
		NonRepeaters:       config.SnmpNonRepeaters,
		AppOpts:            config.SnmpAppOpts,
		ContextEngineID:    config.SnmpContextEngineID,
		ContextName:        config.SnmpContextName,
	}

	if logLevel == "debug" {
		// trapServer.Params.Logger = log.New(os.Stdout, "", 0)
		// DWB changed to use New Logger as per SNMP library update
		trapServer.Params.Logger = gosnmp.NewLogger(log.New(os.Stdout, "", 0))
	}

	err := trapServer.Listen("0.0.0.0:" + strconv.Itoa(int(config.Port)))
	if err != nil {
		log.Printf("[ERROR] createTrapServer - Error encountered invoking trapServer.listen: %s\n", err)
		log.Panicf("Error encountered invoking trapServer.listen: %s\n", err)
	}
}

func snmpTrapHandler(packet *snmp.SnmpPacket, addr *net.UDPAddr) {
	log.Printf("[DEBUG] snmpTrapHandler - Received SNMP trap from %s\n", addr.IP)
	log.Printf("[DEBUG] snmpTrapHandler - Trap data received: %+v\n", packet.Variables)

	//Publish trap data
	trapData := createJSONFromPDUs(packet.Variables)
	fmt.Printf("[DEBUG] formatTrap - Publishing trap data: %+v\n", trapData)
	if trapJSON, err := json.Marshal(trapData); err != nil {
		log.Printf("[ERROR] formatTrap - Error marshalling JSON trap data: %s\n", err.Error())
	} else {
		cbPublish(config.TopicRoot+"/trap", string(trapJSON))
	}
}

func executeSnmpOperation(connection *snmp.GoSNMP, payload adapterRequest) error {
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

	var result interface{}
	var err error

	//	type Asn1BER byte

	// Asn1BER's - http://www.ietf.org/rfc/rfc1442.txt
	//	const (
	//		EndOfContents Asn1BER = 0x00
	//		UnknownType   Asn1BER = 0x00
	//		Boolean       Asn1BER = 0x01
	//		Integer       Asn1BER = 0x02
	//		BitString     Asn1BER = 0x03
	//		OctetString   Asn1BER = 0x04
	//	)

	operation := payload.SnmpOperation

	switch operation {
	case snmpGetOperation:
		result, err = connection.Get(payload.SnmpOIDs) //returns (result *SnmpPacket, err error)
	case snmpGetNextOperation:
		result, err = connection.GetNext(payload.SnmpOIDs) // returns (result *SnmpPacket, err error)
	case snmpGetBulk:
		result, err = connection.GetBulk(payload.SnmpOIDs, uint8(connection.NonRepeaters), connection.MaxRepetitions) // returns (result *SnmpPacket, err error)
	case snmpSetOperation:
		// create a pdu structure to be passed to the Set command
		val := int(payload.SnmpSetValue)
		name := payload.SnmpOIDs[0]
		setType := payload.SnmpSetType
		var a_type gosnmp.Asn1BER = 0
		switch setType {
		case 2:
			a_type = gosnmp.Integer
		default:
			log.Println("[DEBUG] Asn1BER type provided is NOT SUPPORTED1")
		}
		// Will need to account for diverse data types specified in Mib.
		// Works with Integer type for now
		// pdu := snmp.SnmpPDU{
		//	Name:  setOID,
		//	Type:  2,     0x02 is AnsBer type integer, OctetString is 0x04,
		//	Value: payload.SnmpSetValue,
		// }

		pdu := snmp.SnmpPDU{
			Value: val, //payload.SnmpSetValue,
			Name:  name,
			Type:  a_type, // payload.SnmpSetType e.g. 0x02 is AnsBer type integer, OctetString is 0x04,
		}
		var setPdu []snmp.SnmpPDU
		setPdu = append(setPdu, pdu)
		// func (x *GoSNMP) Set(pdus []SnmpPDU) (result *SnmpPacket, err error)
		result, err = connection.Set(setPdu) // returns (result *SnmpPacket, err error)

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

	//Create JSON response
	//Need to see if the results interface is []SnmpPDU or *SnmpPacket.
	//If *SnmpPacket, get Variables value from *SnmpPacket. Variables value is []SnmpPDU
	var pdus []snmp.SnmpPDU
	switch v := result.(type) {
	case *snmp.SnmpPacket:
		//get, getnext, getbulk, set
		pdus = (result.(*snmp.SnmpPacket)).Variables
	case []snmp.SnmpPDU:
		//walkall, bulkwalkall
		pdus = result.([]snmp.SnmpPDU)
	default:
		// And here I'm feeling dumb. ;)
		fmt.Printf("Unsupported type: %v", v)
	}

	response := createJSONFromPDUs(pdus)
	response["request"] = payload

	log.Printf("[DEBUG] executeSnmpOperation - response: %+v\n", response)

	sendResponse(response)
	return nil
}

func createJSONFromPDUs(variables []snmp.SnmpPDU) map[string]interface{} {
	pduJSON := make(map[string]interface{})

	for _, variable := range variables {
		pduJSON[variable.Name] = map[string]interface{}{
			"asn1berType": variable.Type,
		}
		switch variable.Type {
		case snmp.OctetString:
			//TODO - Need to figure out how to transform to string
			// OID: .1.3.6.1.6.3.10.2.1.1.0
			// decodeValue: type is OctetString
			// decodeValue: value is []byte{0x80, 0x0, 0x1f, 0x88, 0x80, 0x38, 0xf7, 0xc1, 0x4b, 0x33, 0x7b, 0xcc, 0x5d, 0x0, 0x0, 0x0, 0x0}
			pduJSON[variable.Name].(map[string]interface{})["value"] = variable.Value.([]byte)
		default:
			pduJSON[variable.Name].(map[string]interface{})["value"] = variable.Value
		}
	}

	return pduJSON
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
