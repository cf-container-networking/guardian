package netplugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os/exec"
	"strings"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/gardener"
	"code.cloudfoundry.org/guardian/kawasaki"
	"code.cloudfoundry.org/lager"
	"github.com/cloudfoundry/gunk/command_runner"
)

const NetworkPropertyPrefix = "network."
const ExternalNetworkPropertyPrefix = "external-networker."
const NetOutKey = NetworkPropertyPrefix + ExternalNetworkPropertyPrefix + "net-out"
const ContainerIPKey = NetworkPropertyPrefix + ExternalNetworkPropertyPrefix + "container-ip"

type ExternalNetworker interface {
	gardener.Networker
	gardener.Starter
}

type ExternalBinaryNetworker struct {
	CommandRunner    command_runner.CommandRunner
	ConfigStore      kawasaki.ConfigStore
	PortPool         kawasaki.PortPool
	ExternalIP       net.IP
	DnsServers       []net.IP
	ResolvConfigurer kawasaki.DnsResolvConfigurer
	Path             string
	ExtraArg         []string
}

func networkProperties(containerProperties garden.Properties) garden.Properties {
	properties := garden.Properties{}

	for k, value := range containerProperties {
		if strings.HasPrefix(k, NetworkPropertyPrefix) {
			key := strings.TrimPrefix(k, NetworkPropertyPrefix)
			properties[key] = value
		}
	}

	return properties
}

func (p *ExternalBinaryNetworker) Start() error { return nil }

func (p *ExternalBinaryNetworker) Network(log lager.Logger, containerSpec garden.ContainerSpec, pid int) error {
	pathAndExtraArgs := append([]string{p.Path}, p.ExtraArg...)
	propertiesJSON, err := json.Marshal(networkProperties(containerSpec.Properties))
	if err != nil {
		return fmt.Errorf("marshaling network properties: %s", err) // not tested
	}

	networkPluginFlags := []string{
		"--handle", containerSpec.Handle,
		"--network", containerSpec.Network,
		"--properties", string(propertiesJSON),
	}

	upArgs := append(pathAndExtraArgs, "--action", "up")
	upArgs = append(upArgs, networkPluginFlags...)

	cmd := exec.Command(p.Path)
	cmd.Args = upArgs
	cmdOutput := &bytes.Buffer{}
	cmd.Stdout = cmdOutput
	cmdStderr := &bytes.Buffer{}
	cmd.Stderr = cmdStderr

	input, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	_, err = io.WriteString(input, fmt.Sprintf("{\"PID\":%d}", pid))
	if err != nil {
		return err
	}
	input.Close()

	err = p.CommandRunner.Run(cmd)
	if err != nil {
		log.Error("external-networker-result", err, lager.Data{"output": cmdStderr.String()})
		return err
	}

	log.Info("external-networker-result", lager.Data{"output": cmdStderr.String()})

	if len(cmdOutput.Bytes()) == 0 {
		return nil
	}

	var properties map[string]map[string]string

	if err := json.Unmarshal(cmdOutput.Bytes(), &properties); err != nil {
		return fmt.Errorf("network plugin returned invalid JSON: %s", err)
	}

	if _, ok := properties["properties"]; !ok {
		return fmt.Errorf("network plugin returned JSON without a properties key")
	}

	for k, v := range properties["properties"] {
		p.ConfigStore.Set(containerSpec.Handle, k, v)
	}

	p.ConfigStore.Set(containerSpec.Handle, gardener.ExternalIPKey, p.ExternalIP.String())

	containerIP, ok := p.ConfigStore.Get(containerSpec.Handle, ContainerIPKey)
	if !ok {
		return fmt.Errorf("no container ip")
	}

	p.ConfigStore.Set(containerSpec.Handle, gardener.ContainerIPKey, containerIP)
	p.ConfigStore.Set(containerSpec.Handle, gardener.BridgeIPKey, containerIP)

	log.Info("external-binary-write-dns-to-config", lager.Data{
		"dnsServers": p.DnsServers,
	})
	cfg := kawasaki.NetworkConfig{
		ContainerIP:     net.ParseIP(containerIP),
		BridgeIP:        net.ParseIP(containerIP),
		ContainerHandle: containerSpec.Handle,
		DNSServers:      p.DnsServers,
	}

	err = p.ResolvConfigurer.Configure(log, cfg, pid)
	if err != nil {
		return err
	}

	return nil
}

func (p *ExternalBinaryNetworker) Destroy(log lager.Logger, handle string) error {
	cleanupTable(log, "filter", handle)
	cleanupTable(log, "nat", handle)

	pathAndExtraArgs := append([]string{p.Path}, p.ExtraArg...)

	networkPluginFlags := []string{
		"--handle", handle,
	}

	downArgs := append(pathAndExtraArgs, "--action", "down")
	downArgs = append(downArgs, networkPluginFlags...)

	cmd := exec.Command(p.Path)
	cmd.Args = downArgs
	return p.CommandRunner.Run(cmd)
}

func cleanupTable(log lager.Logger, table string, handle string) {
	log.Info("external-binary-destroy", lager.Data{
		"table":  table,
		"handle": handle,
	})
	listCmd := exec.Command("/sbin/iptables", "-w", "-t", table, "-S")
	output, err := listCmd.CombinedOutput()
	if err != nil {
		log.Error("external-binary-run-iptables-list", err)
		panic(err)
	}
	ruleList := strings.Split(string(output), "\n")
	deleteRules := []string{}
	for _, r := range ruleList {
		if strings.Contains(r, handle) {
			deleteRules = append(deleteRules, strings.Replace(r, "-A", "-D", -1))
		}
	}

	for _, dr := range deleteRules {
		log.Info("external-binary-run-iptables-delete", lager.Data{
			"table":  table,
			"handle": handle,
			"rule":   dr,
		})
		delArgs := append([]string{"-w", "-t", table}, strings.Split(dr, " ")...)
		delCmd := exec.Command("/sbin/iptables", delArgs...)
		err := delCmd.Run()
		if err != nil {
			log.Error("external-binary-run-iptables-delete", err, lager.Data{
				"args": delArgs,
			})
			panic(err)
		}
	}

}

func (p *ExternalBinaryNetworker) Restore(log lager.Logger, handle string) error {
	return nil
}

func (p *ExternalBinaryNetworker) Capacity() (m uint64) {
	return math.MaxUint64
}

func (p *ExternalBinaryNetworker) NetIn(log lager.Logger, handle string, externalPort, containerPort uint32) (uint32, uint32, error) {
	var err error
	if externalPort == 0 {
		externalPort, err = p.PortPool.Acquire()
		if err != nil {
			return 0, 0, err
		}
	}

	if containerPort == 0 {
		containerPort = externalPort
	}

	if err := kawasaki.AddPortMapping(log, p.ConfigStore, handle, garden.PortMapping{
		HostPort:      externalPort,
		ContainerPort: containerPort,
	}); err != nil {
		return 0, 0, err
	}
	return externalPort, containerPort, nil
}

func (p *ExternalBinaryNetworker) NetOut(log lager.Logger, handle string, rule garden.NetOutRule) error {
	// NEW HOTNESS
	// STORE IN PROPERTIES FOR READING BY NATMAN
	rules := []garden.NetOutRule{}
	value, ok := p.ConfigStore.Get(handle, NetOutKey)
	if ok {
		err := json.Unmarshal([]byte(value), &rules)
		if err != nil {
			return fmt.Errorf("store net-out invalid JSON: %s", err)
		}
	}

	rules = append(rules, rule)
	ruleJSON, err := json.Marshal(rules)
	if err != nil {
		return err
	}

	p.ConfigStore.Set(handle, NetOutKey, string(ruleJSON))

	return nil
}

func parseSubnet(ip string) string {
	octets := strings.Split(ip, ".")
	if len(octets) != 4 {
		panic("invalid ip string")
	}
	return strings.Join(octets[:3], ".") + ".0/24"
}
