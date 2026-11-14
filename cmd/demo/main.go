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

func Discard(args ...interface{}) {}

func addrEq(a, b types.Addr) bool {
    if len(a) != len(b) {
        return false
    }
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}

func unwrap[T any](v T, e error) T {
	if e != nil {
		panic(e)
	}
	return v
}

func main() {
	var logger *log.Logger = log.New(os.Stdout, "", log.Flags())

	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGINT)

	var err error

	keyA := make([]byte, 32)
	unwrap(rand.Read(keyA))
	keyB := make([]byte, 32)
	unwrap(rand.Read(keyB))

	var idA types.Addr
	var idB types.Addr

	{
		var y *yrc.Ygg
		if y, err = yrc.NewYgg(logger, keyA); err != nil {
			logger.Panicln(err)
		}
		unwrap(y.C.ListenLocal(unwrap(url.Parse("tcp://127.42.42.42:10001")), ""))
		unwrap(struct{}{}, y.C.AddPeer(unwrap(url.Parse("tcp://127.42.42.42:10002")), ""))
		idA = []byte(y.C.PublicKey())
		t := yrc.NewTransport(y, ctx)

		t.AcceptPacket = func(from types.Addr, kind int, bytes []byte, err *byte) bool {
			fmt.Printf("\x1b[95m%s\x1b[39m \x1b[94m--\x1b[39m %d [%d]\n", hex.EncodeToString(from)[:8], kind, len(bytes))
			return addrEq(from, idB)
		}

		t.OnSendUpdate = func(to types.Addr, ident yrc.Ident, progress []bool, errCode byte) {
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

		go func() {
			time.Sleep(time.Second * 5)
			t.SendMessage([]byte("Hello!"), idB)
		}()
	}

	{
		var y *yrc.Ygg
		if y, err = yrc.NewYgg(logger, keyB); err != nil {
			logger.Panicln(err)
		}
		unwrap(y.C.ListenLocal(unwrap(url.Parse("tcp://127.42.42.42:10002")), ""))
		unwrap(struct{}{},y.C.AddPeer(unwrap(url.Parse("tcp://127.42.42.42:10001")), ""))
		idB = []byte(y.C.PublicKey())
		t := yrc.NewTransport(y, ctx)

		t.AcceptPacket = func(from types.Addr, kind int, bytes []byte, err *byte) bool {
			fmt.Printf("\x1b[96m%s\x1b[39m \x1b[94m--\x1b[39m %d [%d]\n", hex.EncodeToString(from)[:8], kind, len(bytes))
			return addrEq(from, idA)
		}

		t.AcceptMessage = func(from types.Addr, ident yrc.Ident, err *byte) bool {
			fmt.Printf("\x1b[96m%s\x1b[39m \x1b[94m~~\x1b[39m {%s} %+v\n", hex.EncodeToString(from)[:8], hex.EncodeToString(ident.MessageKey(from)), ident)
			return addrEq(from, idA)
		}

		t.OnRecvUpdate = func(from types.Addr, ident yrc.Ident, progress []bool, errCode byte) {
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

		t.OnMessage = func(from types.Addr, ident yrc.Ident, bytes []byte) {
			fmt.Printf("\x1b[96m%s\x1b[39m \x1b[92m##\x1b[39m {%s} %q\n", hex.EncodeToString(from)[:8], ident.MessageKeyHex(from), string(bytes))
		}
	}

	fmt.Printf("\x1b[95m%s\x1b[39m :: A\n\x1b[96m%s\x1b[39m :: B\n\n", hex.EncodeToString(idA)[:8], hex.EncodeToString(idB)[:8])

	<-ctx.Done()
}
