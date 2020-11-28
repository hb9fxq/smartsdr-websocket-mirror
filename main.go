package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/hb9fxq/flexlib-go/obj"
	"github.com/hb9fxq/flexlib-go/sdrobjects"
	"github.com/hb9fxq/flexlib-go/vita"
	"log"
	"net/http"
	"strings"
	"time"
)

var rc *obj.RadioContext

var pcapChanUdp = make(chan []byte)
var pcapChanTcp = make(chan string)
var hub *Hub

var (
	MSG_PAN   = []byte{'P', ' '}
	MSG_SLICE = []byte{'S', ' '}
	MSG_FFT   = []byte{'F', ' '}
	MSG_OPUS  = []byte{'O', ' '}
)

type AppContext struct {
	httpListenAddress string
	radioIp           string
	pcapInterface     string
}

var appContext = new(AppContext)

func main() {

	flag.StringVar(&appContext.httpListenAddress, "HTTPLISTEN", "0.0.0.0:8283", "")
	flag.StringVar(&appContext.radioIp, "RADIOIP", "192.168.92.8", "Flex Radio IP Address")
	flag.StringVar(&appContext.pcapInterface, "IF", "en0", "local interface to sniff VITA-49 traffic")
	flag.Parse()

	rc = new(obj.RadioContext)
	rc.RadioAddr = appContext.radioIp
	rc.Debug = true
	rc.ChannelRadioResponse = make(chan string)
	rc.MyUdpEndpointPort = "7598"
	go obj.InitRadioContext(rc)

	go func(ctx *obj.RadioContext) {
		for {
			res := <-ctx.ChannelRadioResponse
			fmt.Println(res)
		}
	}(rc)

	go pushRadioStates()
	go dispatchUdpPackets()
	go dispatchTcpPackets()
	go pullPcap()

	hub = newHub()
	go hub.run()

	serveHome()
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	})
	err := http.ListenAndServe(appContext.httpListenAddress, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

}

func dispatchTcpPackets() {
	for {
		message := <-pcapChanTcp
		message = strings.Trim(message, "\n")
		fmt.Println("PCAPTCPMESSAGE>>>>>>" + message)

		// need to parse, because response does not contain dimensions
		if strings.Contains(message, "display pan set ") && strings.Contains(message, "ixel") {
			obj.ParseResponseLine(rc, message)
		}
	}
}

func dispatchUdpPackets() {
	for {
		message := <-pcapChanUdp
		err, preamble, payload := vita.ParseVitaPreamble(message)

		if err != nil || preamble.Class_id == nil {
			continue
		}

		switch preamble.Header.Pkt_type {

		case vita.ExtDataWithStream:

			switch preamble.Class_id.PacketClassCode {

			case vita.SL_VITA_FFT_CLASS:
				pkg := vita.ParseVitaFFT(payload, preamble)
				handleFFTPackage(preamble, pkg)
				break
			case vita.SL_VITA_OPUS_CLASS:
				pkg := vita.ParseVitaOpus(payload, preamble)
				handleOpusPackage(preamble, pkg)
				break
			case vita.SL_VITA_IF_NARROW_CLASS:
				fmt.Println("SL_VITA_IF_NARROW_CLASS")
				break
			case vita.SL_VITA_METER_CLASS:
				vita.ParseVitaMeterPacket(payload, preamble)
				break
			case vita.SL_VITA_DISCOVERY_CLASS:
				break
			case vita.SL_VITA_WATERFALL_CLASS:
				break
			default:
				fmt.Println("UNKNOWN VITA TYPE")
				break
			}

			break

		case vita.IFDataWithStream:
			switch preamble.Class_id.InformationClassCode {
			case vita.SL_VITA_IF_WIDE_CLASS_24kHz:
			case vita.SL_VITA_IF_WIDE_CLASS_48kHz:
			case vita.SL_VITA_IF_WIDE_CLASS_96kHz:
			case vita.SL_VITA_IF_WIDE_CLASS_192kHz:
			}
			break
		}
	}
}

func handleOpusPackage(preamble *vita.VitaPacketPreamble, pkg []byte) {
	res := append(MSG_OPUS, pkg...)
	hub.broadcast <- res
}

type FftHandle struct {
	Missing    uint16
	FrameIndex uint32
	Buffer     []byte
}

var fftHandles = make(map[string]*FftHandle)

func handleFFTPackage(preamble *vita.VitaPacketPreamble, pkg *sdrobjects.SdrFFTPacket) {

	streamHexString := fmt.Sprintf("%X", preamble.Stream_id)
	streamHexStringMsg := append(MSG_FFT, []byte(streamHexString)...)

	if fftHandles[streamHexString] == nil {
		fftHandles[streamHexString] = &FftHandle{}
		fftHandles[streamHexString].Missing = pkg.TotalBinsInFrame
	}

	handle := fftHandles[streamHexString]

	if handle.FrameIndex != pkg.FrameIndex {
		handle.Missing = pkg.TotalBinsInFrame
	}

	b := make([]byte, 2)

	// todo: find smarter way
	for _, val := range pkg.Payload {

		binary.LittleEndian.PutUint16(b, val)
		handle.Buffer = append(handle.Buffer, b...)
	}

	handle.FrameIndex = pkg.FrameIndex
	handle.Missing -= pkg.NumBins

	if handle.Missing == 0 {
		res := append(streamHexStringMsg, handle.Buffer...)
		hub.broadcast <- res
		handle.Buffer = []byte{}
	}
}

func pullPcap() {
	if handle, err := pcap.OpenLive(appContext.pcapInterface, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("port 4993 or port 4992"); err != nil {
		panic(err)
	} else {

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {

			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			applicationLayer := packet.ApplicationLayer()
			if tcpLayer != nil && applicationLayer != nil {
				pcapChanTcp <- fmt.Sprintf("%s", applicationLayer.Payload())
			}

			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				pcapChanUdp <- packet.ApplicationLayer().Payload()
			}

		}
	}
}

func serveHome() {
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

}

func pushRadioStates() {
	for {
		jsonPanadapters := make(map[string]interface{})
		rc.Panadapters.Range(func(k interface{}, value interface{}) bool {
			jsonPanadapters[k.(string)] = value
			return true
		})

		j, err := json.Marshal(&jsonPanadapters)

		if err != nil {
			fmt.Println(err)
			continue
		}

		hub.broadcast <- append(MSG_PAN, j...)
		fmt.Println("Broadcast " + string(j))
		time.Sleep(1 * time.Second)
	}
}
