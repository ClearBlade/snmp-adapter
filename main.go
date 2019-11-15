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
	snmp "github.com/soniah/gosnmp"
)

const (
	platURL                        = "http://localhost:9000"
	messURL                        = "localhost:1883"
	msgSubscribeQos                = 0
	msgPublishQos                  = 0
	adapterConfigCollectionDefault = "adapter_config"
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
	topicRoot = "cb/snmp"

	cbBroker           cbPlatformBroker
	cbSubscribeChannel <-chan *mqttTypes.Publish
	endWorkersChannel  chan string
	interruptChannel   chan os.Signal
)

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

type adapterRequest struct {
	SnmpAddress               string   `json:"snmpAddress"`
	SnmpPort                  uint16   `json:"snmpPort"`
	SnmpOIDs                  []string `json:"snmpOIDs"`
	SnmpVersion               int      `json:"snmpVersion"`
	SnmpCommunity             string   `json:"snmpCommunity"`
	SnmpOperation             string   `json:"snmpOperation"`
	SnmpGetBulkNonRepeaters   uint8    `json:"snmpGetBulkNonRepeaters"`
	SnmpGetBulkMaxRepetitions uint8    `json:"snmpGetBulkMaxRepetitions"`
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

//If the connection to the broker is lost, we need to reconnect and
//re-establish all of the subscriptions
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

//When the connection to the broker is complete, set up any subscriptions
//and authenticate the google pubsub client
func onConnect(client mqtt.Client) {
	log.Println("[INFO] OnConnect - Connected to ClearBlade Platform MQTT broker")

	//CleanSession, by default, is set to true. This results in non-durable subscriptions.
	//We therefore need to re-subscribe
	log.Println("[INFO] OnConnect - Begin configuring platform subscription")

	var err error
	//TODO - Fix topic when we decide what the structure will look like
	for cbSubscribeChannel, err = cbSubscribe(topicRoot + "/request"); err != nil; {
		//Wait 30 seconds and retry
		log.Printf("[ERROR] OnConnect - Error subscribing to MQTT: %s\n", err.Error())
		log.Println("[ERROR] OnConnect - Will retry in 30 seconds...")
		time.Sleep(time.Duration(30 * time.Second))
		cbSubscribeChannel, err = cbSubscribe(topicRoot + "/request")
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
	var settingsJSON map[string]interface{}

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
		if len(results["DATA"].([]interface{})) > 0 {
			log.Printf("[DEBUG] getAdapterConfig - Adapter config retrieved: %#v\n", results)
			log.Println("[INFO] getAdapterConfig - Adapter config retrieved")

			//MQTT topic root
			if results["DATA"].([]interface{})[0].(map[string]interface{})["topic_root"] != nil {
				log.Printf("[DEBUG] getAdapterConfig - Setting topicRoot to %s\n", results["DATA"].([]interface{})[0].(map[string]interface{})["topic_root"].(string))
				topicRoot = results["DATA"].([]interface{})[0].(map[string]interface{})["topic_root"].(string)
			} else {
				log.Printf("[INFO] getAdapterConfig - Topic root is nil. Using default value %s\n", topicRoot)
			}

			//adapter_settings
			log.Println("[DEBUG] getAdapterConfig - Retrieving adapter settings...")
			if results["DATA"].([]interface{})[0].(map[string]interface{})["adapter_settings"] != nil {
				if err := json.Unmarshal([]byte(results["DATA"].([]interface{})[0].(map[string]interface{})["adapter_settings"].(string)), &settingsJSON); err != nil {
					log.Printf("[ERROR] getAdapterConfig - Error while unmarshalling json: %s. Defaulting all adapter settings.\n", err.Error())
				}
			} else {
				log.Println("[INFO] applyAdapterConfig - Settings are nil. Defaulting all adapter settings.")
			}
		} else {
			log.Println("[INFO] getAdapterConfig - No rows returned. Using defaults")
		}
	}

	if settingsJSON == nil {
		settingsJSON = make(map[string]interface{})
	}

	applyAdapterSettings(settingsJSON)
}

func applyAdapterSettings(adapterSettings map[string]interface{}) {
	//shouldHandleTraps
	if adapterSettings["shouldHandleTraps"] != nil {
		if adapterSettings["shouldHandleTraps"].(bool) == true {
			log.Println("[INFO] applyAdapterConfig - shouldHandleTraps is true, starting SNMP trap server")

			if adapterSettings["trapServerPort"] != nil {
				log.Println("[INFO] applyAdapterConfig - Starting trap server on port " + strconv.Itoa(int(adapterSettings["trapServerPort"].(float64))))
				go createTrapServer(strconv.Itoa(int(adapterSettings["trapServerPort"].(float64))))
			} else {
				log.Printf("[INFO] applyAdapterSettings - A trapServerPort value was not found.\n")
			}
		}
	} else {
		log.Printf("[INFO] applyAdapterSettings - A shouldHandleTraps value was not found.\n")
	}
}

func getConnection(payload adapterRequest) (*snmp.GoSNMP, error) {
	//TODO - Need to figure out if/when we use the default connection parameter
	log.Println("[DEBUG] getConnection - Verifying connection parameters")

	if payload.SnmpAddress == "" {
		log.Printf("[ERROR] getConnection - snmpAddress not specified in incoming payload: %+v\n", payload)
		return nil, errors.New("snmpAddress not specified in incoming payload")
	}

	if payload.SnmpPort == 0 {
		log.Printf("[ERROR] getConnection - snmpPort not specified in incoming payload: %+v\n", payload)
		return nil, errors.New("snmpPort not specified in incoming payload")
	}

	if payload.SnmpCommunity == "" {
		log.Printf("[ERROR] getConnection - snmpCommunity not specified in incoming payload: %+v\n", payload)
		return nil, errors.New("snmpCommunity not specified in incoming payload")
	}

	if payload.SnmpVersion == 0 {
		log.Printf("[ERROR] getConnection - snmpVersion not specified in incoming payload: %+v\n", payload)
		return nil, errors.New("snmpVersion not specified in incoming payload")
	}

	params := &snmp.GoSNMP{
		Target:    payload.SnmpAddress,
		Port:      payload.SnmpPort,
		Community: payload.SnmpCommunity,
		Timeout:   time.Duration(2) * time.Second,
		MaxOids:   1,
	}

	switch payload.SnmpVersion {
	case 1:
		params.Version = snmp.Version1
	case 2:
		params.Version = snmp.Version2c
	case 3:
		params.Version = snmp.Version3
	default:
		log.Printf("[ERROR] getConnection - Invalid version specified: %+v\n", payload.SnmpVersion)
		return nil, fmt.Errorf("Invalid version specified: %+v", payload.SnmpVersion)
	}
	log.Printf("[DEBUG] getConnection - Version set to %+v\n", params.Version)

	if logLevel == "debug" {
		params.Logger = log.New(os.Stdout, "", 0)
	}

	return params, params.Connect()
}

func sendResponse(returnData map[string]interface{}) {
	response, err := json.Marshal(returnData)

	if err == nil {
		cbPublish(topicRoot+"/response", string(response))
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
		cbPublish(topicRoot+"/error", string(response))
	} else {
		log.Printf("[ERROR] sendErrorResponse - Error marshalling JSON: %s\n", err.Error())
	}
}

func createTrapServer(port string) {
	trapServer = snmp.NewTrapListener()
	trapServer.OnNewTrap = snmpTrapHandler

	//TODO - Need to determine if default params should be used or if we need to use our own values
	trapServer.Params = snmp.Default
	trapServer.Params.Logger = log.New(os.Stdout, "", 0)

	err := trapServer.Listen("0.0.0.0:" + port)
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
	trapJSON, err := json.Marshal(trapData)

	if err != nil {
		cbPublish(topicRoot+"/trap", string(trapJSON))
	} else {
		log.Printf("[ERROR] formatTrap - Error marshalling JSON trap data: %s\n", err.Error())
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

	//TODO - Determine if operation should be in topic structure
	operation := payload.SnmpOperation

	switch operation {
	case snmpGetOperation:
		result, err = connection.Get(payload.SnmpOIDs) //returns (result *SnmpPacket, err error)
	case snmpGetNextOperation:
		result, err = connection.GetNext(payload.SnmpOIDs) // returns (result *SnmpPacket, err error)
	case snmpGetBulk:
		// if payload.SnmpGetBulkNonRepeaters == 0 {
		// 	//TODO see about defaulting
		// 	err = errors.New("snmpGetBulkNonRepeaters not provided in payload. Cannot execute getbulk operation")
		// }

		// //TODO see about defaulting
		// if payload.SnmpGetBulkMaxRepetitions == 0 {
		// 	err = errors.New("snmpGetBulkMaxRepetitions not provided in payload. Cannot execute getbulk operation")
		// }

		result, err = connection.GetBulk(payload.SnmpOIDs, payload.SnmpGetBulkNonRepeaters, payload.SnmpGetBulkMaxRepetitions) // returns (result *SnmpPacket, err error)
	case snmpSetOperation:
		//Will need to account for data type specified in Mib.

		// pdu := snmp.SnmpPDU{
		// 	Name:  payload["snmpOIDs"].([]string)[0],
		// 	Type:  OctetString,
		// 	Value: trapTestPayload,
		// }
		// result, err = connection.Set //(payload["snmpOIDs"].([]string)) // returns (result *SnmpPacket, err error)

		err = errors.New("SNMP set currently not supported") // returns error
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

	sendResponse(createJSONFromPDUs(pdus))
	return nil
}

func createJSONFromPDUs(variables []snmp.SnmpPDU) map[string]interface{} {
	pduJSON := make(map[string]interface{})

	for _, variable := range variables {
		switch variable.Type {
		case snmp.OctetString:
			//TODO - Need to figure out how to transform to string
			// OID: .1.3.6.1.6.3.10.2.1.1.0
			// decodeValue: type is OctetString
			// decodeValue: value is []byte{0x80, 0x0, 0x1f, 0x88, 0x80, 0x38, 0xf7, 0xc1, 0x4b, 0x33, 0x7b, 0xcc, 0x5d, 0x0, 0x0, 0x0, 0x0}
			pduJSON[variable.Name] = variable.Value.([]byte)
		default:
			pduJSON[variable.Name] = variable.Value
		}
	}

	return pduJSON
}
