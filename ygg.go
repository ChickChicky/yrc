package yrc

import (
	"crypto/ed25519"
	"encoding/hex"
	"regexp"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/multicast"
)

// Convenience for Yggdrasil core and multicast initialization and destruction
type Ygg struct {
	Log core.Logger
	C *core.Core
	M *multicast.Multicast
}

func NewYgg(logger core.Logger, key config.KeyBytes) (*Ygg, error) {
	ygg := &Ygg{
		Log: logger,
	}

	cfg := config.GenerateConfig()

	// Basic config
	{
		cfg.PrivateKey = key
		cfg.AdminListen = "none"
		cfg.NodeInfoPrivacy = true // kinda useless
	}

	cfg.GenerateSelfSignedCertificate()

	privateKey := ed25519.PrivateKey(cfg.PrivateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	var err error

	// Setup core
	{
		options := []core.SetupOption{
			core.NodeInfo(cfg.NodeInfo),
			core.NodeInfoPrivacy(cfg.NodeInfoPrivacy),
		}
		for _, addr := range cfg.Listen {
			options = append(options, core.ListenAddress(addr))
		}
		for _, peer := range cfg.Peers {
			options = append(options, core.Peer{URI: peer})
		}
		for intf, peers := range cfg.InterfacePeers {
			for _, peer := range peers {
				options = append(options, core.Peer{URI: peer, SourceInterface: intf})
			}
		}
		for _, allowed := range cfg.AllowedPublicKeys {
			k, err := hex.DecodeString(allowed)
			if err != nil {
				panic(err)
			}
			options = append(options, core.AllowedPublicKey(k[:]))
		}
		if ygg.C, err = core.New(cfg.Certificate, logger, options...); err != nil {
			return nil, err
		}
	}

	// Setup multicast
	{
		options := []multicast.SetupOption{}
		for _, intf := range cfg.MulticastInterfaces {
			options = append(options, multicast.MulticastInterface{
				Regex:    regexp.MustCompile(intf.Regex),
				Beacon:   intf.Beacon,
				Listen:   intf.Listen,
				Port:     intf.Port,
				Priority: uint8(intf.Priority),
				Password: intf.Password,
			})
		}
		if ygg.M, err = multicast.New(ygg.C, logger, options...); err != nil {
			return nil, err
		}
	}

	logger.Debugln("Connected", hex.EncodeToString(publicKey))

	return ygg, nil
}

func (y *Ygg) Close() {
	// TODO: Return error?
	err := y.C.Close()
	if err != nil {
		y.Log.Errorln(err)
	}
	err = y.M.Stop()
	if err != nil {
		y.Log.Errorln(err)
	}
}
