package netplugin

import (
	"bytes"
	"encoding/json"
	"fmt"
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
const NetOutKey = NetworkPropertyPrefix + "external-networker.net-out"

type externalBinaryNetworker struct {
	commandRunner    command_runner.CommandRunner
	configStore      kawasaki.ConfigStore
	portPool         kawasaki.PortPool
	externalIP       net.IP
	dnsServers       []net.IP
	resolvConfigurer kawasaki.DnsResolvConfigurer
	path             string
	extraArg         []string
}

func New(
	commandRunner command_runner.CommandRunner,
	configStore kawasaki.ConfigStore,
	portPool kawasaki.PortPool,
	externalIP net.IP,
	dnsServers []net.IP,
	resolvConfigurer kawasaki.DnsResolvConfigurer,
	path string,
	extraArg []string,
) ExternalNetworker {
	return &externalBinaryNetworker{
		commandRunner:    commandRunner,
		configStore:      configStore,
		portPool:         portPool,
		externalIP:       externalIP,
		dnsServers:       dnsServers,
		resolvConfigurer: resolvConfigurer,
		path:             path,
		extraArg:         extraArg,
	}
}

type ExternalNetworker interface {
	gardener.Networker
	gardener.Starter
}

func (p *externalBinaryNetworker) Start() error { return nil }

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

func (p *externalBinaryNetworker) Network(log lager.Logger, containerSpec garden.ContainerSpec, pid int) error {
	p.configStore.Set(containerSpec.Handle, gardener.ExternalIPKey, p.externalIP.String())

	propertiesJSON, err := json.Marshal(networkProperties(containerSpec.Properties))
	if err != nil {
		return fmt.Errorf("marshaling network properties: %s", err) // not tested
	}

	cmdFlags := []string{
		"--network", containerSpec.Network,
		"--properties", string(propertiesJSON),
	}
	stdin := fmt.Sprintf("{\"PID\":%d}", pid)
	cmdOutput, err := p.exec(log, "up", containerSpec.Handle, stdin, cmdFlags...)
	if err != nil {
		return err
	}

	if len(cmdOutput) == 0 {
		return nil
	}

	var properties map[string]map[string]string

	if err := json.Unmarshal(cmdOutput, &properties); err != nil {
		return fmt.Errorf("network plugin returned invalid JSON: %s", err)
	}

	if _, ok := properties["properties"]; !ok {
		return fmt.Errorf("network plugin returned JSON without a properties key")
	}

	for k, v := range properties["properties"] {
		p.configStore.Set(containerSpec.Handle, k, v)
	}

	containerIP, ok := p.configStore.Get(containerSpec.Handle, gardener.ContainerIPKey)
	if !ok {
		return fmt.Errorf("no container ip")
	}

	log.Info("external-binary-write-dns-to-config", lager.Data{
		"dnsServers": p.dnsServers,
	})
	cfg := kawasaki.NetworkConfig{
		ContainerIP:     net.ParseIP(containerIP),
		BridgeIP:        net.ParseIP(containerIP),
		ContainerHandle: containerSpec.Handle,
		DNSServers:      p.dnsServers,
	}

	err = p.resolvConfigurer.Configure(log, cfg, pid)
	if err != nil {
		return err
	}

	return nil
}

func (p *externalBinaryNetworker) Destroy(log lager.Logger, handle string) error {
	_, err := p.exec(log, "down", handle, "")
	return err
}

func (p *externalBinaryNetworker) Restore(log lager.Logger, handle string) error {
	return nil
}

func (p *externalBinaryNetworker) Capacity() (m uint64) {
	return math.MaxUint64
}

func (p *externalBinaryNetworker) exec(log lager.Logger, action, handle, stdin string, cmdArgs ...string) ([]byte, error) {
	args := append([]string{p.path}, p.extraArg...)
	args = append(args, "--action", action, "--handle", handle)
	cmd := exec.Command(p.path)
	cmd.Args = append(args, cmdArgs...)
	stdout := &bytes.Buffer{}
	cmd.Stdout = stdout
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	cmd.Stdin = strings.NewReader(stdin)

	err := p.commandRunner.Run(cmd)
	logData := lager.Data{"stderr": stderr.String(), "stdout": stdout.String()}
	if err != nil {
		log.Error("external-networker-result", err, logData)
		return stdout.Bytes(), fmt.Errorf("external networker: %s", err)
	}
	log.Info("external-networker-result", logData)
	return stdout.Bytes(), nil
}

func (p *externalBinaryNetworker) NetIn(log lager.Logger, handle string, hostPort, containerPort uint32) (uint32, uint32, error) {
	cmdFlags := []string{
		"--host-port", fmt.Sprintf("%d", hostPort),
		"--container-port", fmt.Sprintf("%d", containerPort),
	}
	stdout, err := p.exec(log, "net-in", handle, "", cmdFlags...)
	if err != nil {
		return 0, 0, err
	}

	var result struct {
		HostPort      uint32 `json:"host_port"`
		ContainerPort uint32 `json:"container_port"`
	}
	err = json.Unmarshal(stdout, &result)
	if err != nil {
		return 0, 0, err
	}

	err = kawasaki.AddPortMapping(log, p.configStore, handle, garden.PortMapping{
		HostPort:      result.HostPort,
		ContainerPort: result.ContainerPort,
	})

	return result.HostPort, result.ContainerPort, err
}

func (p *externalBinaryNetworker) NetOut(log lager.Logger, handle string, rule garden.NetOutRule) error {
	rules := []garden.NetOutRule{}
	value, ok := p.configStore.Get(handle, NetOutKey)
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

	p.configStore.Set(handle, NetOutKey, string(ruleJSON))
	return nil
}
