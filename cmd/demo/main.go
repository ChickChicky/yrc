package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "net/http/pprof"

	"github.com/Arceliar/ironwood/types"
	"github.com/ChickChicky/yrc"
	"github.com/gologme/log"
)

// Checks whether two addresses are equal
func addrEq(a, b types.Addr) bool {
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}

// Takes a value and an error, panics if the error is not nil, otherwise returns the first value
func unwrap[T any](v T, e error) T {
	if e != nil {
		panic(e)
	}
	return v
}

// Very basic demo of a node sending a message to another
func main() {
	var logger *log.Logger = log.New(os.Stdout, "", log.Flags())

	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGINT)

	// Generates random private keys for A and B
	keyA := make([]byte, 32)
	unwrap(rand.Read(keyA))
	keyB := make([]byte, 32)
	unwrap(rand.Read(keyB))

	// Public key for a and b
	var idA, idB types.Addr

	// A side (sender)
	{
		// Initialize Yrc
		y := unwrap(yrc.New(keyA, logger, ctx))
		idA = []byte(y.C.PublicKey())

		// Creates an Yggdrasil server on port 10001 and connects to the one on port 10002
		unwrap(y.C.ListenLocal(unwrap(url.Parse("tcp://127.42.42.42:10001")), ""))
		unwrap(struct{}{}, y.C.AddPeer(unwrap(url.Parse("tcp://127.42.42.42:10002")), ""))

		// Function to control which packets are accepted
		// should be used for example to allow processing packets from contacts, but reject from unknown peers
		y.AcceptPacket = func(from types.Addr, kind int, bytes []byte, err *byte) bool {
			fmt.Printf("\x1b[95m%s\x1b[39m \x1b[94m--\x1b[39m %d [%d]\n", hex.EncodeToString(from)[:8], kind, len(bytes))
			return addrEq(from, idB)
		}

		// Called whenever a FragAck/FragNak has been received
		// used to see the status of the message,
		// progress is a slice that contains a boolean for each fragment of the message, and whether it is sent (true) or staged/flying (false)
		// errCode contains the last error that has occured, if not ErrOkay, then the message has been cancelled
		y.OnSendUpdate = func(to types.Addr, ident yrc.Ident, progress []bool, errCode byte) {
			sent := 0
			bars := strings.Builder{}
			bars.Grow(int(ident.FragCount()))
			for _, it := range progress {
				if it { 
					sent++
					bars.WriteRune('#')
				} else {
					bars.WriteRune('.')
				}
			}
			col := '2'
			if errCode != yrc.ErrOkay {
				col = '1'
			}
			fmt.Printf("\x1b[95m........\x1b[39m \x1b[9%cm>>\x1b[39m {%s} [%s] (%.2f%%) (%d) <%d>\n", col, ident.MessageKeyHex(to), bars.String(), float32(sent)/float32(ident.FragCount())*100, errCode, ident.Index)
		}

		// Waits a few seconds for the nodes to properly connect and then sends the message
		go func() {
			time.Sleep(time.Second * 5)
			y.SendMessage([]byte("Hello!"), idB)
		}()
	}

	// B side (recipient)
	{
		// Initialize Yrc
		y := unwrap(yrc.New(keyB, logger, ctx))
		idB = []byte(y.C.PublicKey())

		// Creates an Yggdrasil server on port 10002 and connects to the one on port 10001
		unwrap(y.C.ListenLocal(unwrap(url.Parse("tcp://127.42.42.42:10002")), ""))
		unwrap(struct{}{},y.C.AddPeer(unwrap(url.Parse("tcp://127.42.42.42:10001")), ""))

		// see above
		y.AcceptPacket = func(from types.Addr, kind int, bytes []byte, err *byte) bool {
			fmt.Printf("\x1b[96m%s\x1b[39m \x1b[94m--\x1b[39m %d [%d]\n", hex.EncodeToString(from)[:8], kind, len(bytes))
			return addrEq(from, idA)
		}

		// Similar to AcceptPacket, but for an entire message
		y.AcceptMessage = func(from types.Addr, ident yrc.Ident, err *byte) bool {
			fmt.Printf("\x1b[96m%s\x1b[39m \x1b[94m~~\x1b[39m {%s} %+v\n", hex.EncodeToString(from)[:8], hex.EncodeToString(ident.MessageKey(from)), ident)
			return addrEq(from, idA)
		}

		// Similar to OnSendUpdate, but for the recipient side
		y.OnRecvUpdate = func(from types.Addr, ident yrc.Ident, progress []bool, errCode byte) {
			sent := 0
			bars := strings.Builder{}
			bars.Grow(int(ident.FragCount()))
			for _, it := range progress {
				if it { 
					sent++
					bars.WriteRune('#')
				} else {
					bars.WriteRune('.')
				}
			}
			col := '2'
			if errCode != yrc.ErrOkay {
				col = '1'
			}
			fmt.Printf("\x1b[96m%s\x1b[39m \x1b[9%cm<<\x1b[39m {%s} [%s] (%.2f%%) (%d) <%d>\n", hex.EncodeToString(from)[:8], col, ident.MessageKeyHex(from), bars.String(), float32(sent)/float32(ident.FragCount())*100, errCode, ident.Index)
		}

		// Called when a message has fully been received
		y.OnMessage = func(from types.Addr, ident yrc.Ident, bytes []byte) {
			fmt.Printf("\x1b[96m%s\x1b[39m \x1b[92m##\x1b[39m {%s} %q\n", hex.EncodeToString(from)[:8], ident.MessageKeyHex(from), string(bytes))
		}
	}

	fmt.Printf("\x1b[95m%s\x1b[39m :: A\n\x1b[96m%s\x1b[39m :: B\n\n", hex.EncodeToString(idA)[:8], hex.EncodeToString(idB)[:8])

	<-ctx.Done()
}
