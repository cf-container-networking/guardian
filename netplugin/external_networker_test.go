package netplugin_test

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"os/exec"

	"code.cloudfoundry.org/garden"
	"code.cloudfoundry.org/guardian/gardener"
	"code.cloudfoundry.org/guardian/kawasaki"
	"code.cloudfoundry.org/guardian/kawasaki/kawasakifakes"
	"code.cloudfoundry.org/guardian/netplugin"
	"code.cloudfoundry.org/guardian/properties"
	"code.cloudfoundry.org/lager/lagertest"
	"github.com/cloudfoundry/gunk/command_runner/fake_command_runner"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

func mustMarshalJSON(input interface{}) string {
	bytes, err := json.Marshal(input)
	Expect(err).NotTo(HaveOccurred())
	return string(bytes)
}

var _ = Describe("ExternalNetworker", func() {
	var (
		containerSpec     garden.ContainerSpec
		configStore       kawasaki.ConfigStore
		fakeCommandRunner *fake_command_runner.FakeCommandRunner
		logger            *lagertest.TestLogger
		plugin            netplugin.ExternalNetworker
		handle            string
		resolvConfigurer  *kawasakifakes.FakeDnsResolvConfigurer
		portPool          *kawasakifakes.FakePortPool
	)

	BeforeEach(func() {
		inputProperties := garden.Properties{
			"some-key":               "some-value",
			"some-other-key":         "some-other-value",
			"network.some-key":       "some-network-value",
			"network.some-other-key": "some-other-network-value",
		}
		fakeCommandRunner = fake_command_runner.New()
		configStore = properties.NewManager()
		handle = "some-handle"
		containerSpec = garden.ContainerSpec{
			Handle:     "some-handle",
			Network:    "potato",
			Properties: inputProperties,
		}
		logger = lagertest.NewTestLogger("test")
		portPool = &kawasakifakes.FakePortPool{}
		externalIP := net.ParseIP("1.2.3.4")
		dnsServers := []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("9.9.9.9")}
		resolvConfigurer = &kawasakifakes.FakeDnsResolvConfigurer{}
		plugin = netplugin.New(
			fakeCommandRunner,
			configStore,
			portPool,
			externalIP,
			dnsServers,
			resolvConfigurer,
			"some/path",
			[]string{"arg1", "arg2", "arg3"},
		)
	})

	Describe("Network", func() {
		var pluginOutput string
		var pluginErr error

		BeforeEach(func() {
			pluginErr = nil
			fakeCommandRunner.WhenRunning(fake_command_runner.CommandSpec{
				Path: "some/path",
			}, func(cmd *exec.Cmd) error {
				cmd.Stdout.Write([]byte(pluginOutput))
				cmd.Stderr.Write([]byte("some-stderr-bytes"))
				return pluginErr
			})
			pluginOutput = `{ "properties": {
					"garden.network.container-ip": "10.255.1.2"
					}
				}`
		})

		It("sets the external-ip property on the container", func() {
			err := plugin.Network(logger, containerSpec, 42)
			Expect(err).NotTo(HaveOccurred())

			externalIPValue, _ := configStore.Get(handle, gardener.ExternalIPKey)
			Expect(externalIPValue).To(Equal("1.2.3.4"))
		})

		It("passes the pid of the container to the external plugin's stdin", func() {
			err := plugin.Network(logger, containerSpec, 42)
			Expect(err).NotTo(HaveOccurred())

			cmd := fakeCommandRunner.ExecutedCommands()[0]
			input, err := ioutil.ReadAll(cmd.Stdin)
			Expect(err).NotTo(HaveOccurred())

			Expect(string(input)).To(ContainSubstring("42"))
		})

		It("executes the external plugin with the correct args", func() {
			err := plugin.Network(logger, containerSpec, 42)
			Expect(err).NotTo(HaveOccurred())

			cmd := fakeCommandRunner.ExecutedCommands()[0]
			Expect(cmd.Path).To(Equal("some/path"))

			Expect(cmd.Args[:10]).To(Equal([]string{
				"some/path",
				"arg1",
				"arg2",
				"arg3",
				"--action", "up",
				"--handle", "some-handle",
				"--network", "potato",
			}))

			Expect(cmd.Args[10]).To(Equal("--properties"))
			Expect(cmd.Args[11]).To(MatchJSON(`{
					"some-key":       "some-network-value",
					"some-other-key": "some-other-network-value"
			}`))
		})

		It("collects and logs the stderr from the plugin", func() {
			err := plugin.Network(logger, containerSpec, 42)
			Expect(err).NotTo(HaveOccurred())

			Expect(logger).To(gbytes.Say("result.*some-stderr-bytes"))
		})

		It("configures DNS inside the container", func() {
			err := plugin.Network(logger, containerSpec, 42)
			Expect(err).NotTo(HaveOccurred())

			Expect(resolvConfigurer.ConfigureCallCount()).To(Equal(1))
			log, cfg, pid := resolvConfigurer.ConfigureArgsForCall(0)
			Expect(log).To(Equal(logger))
			Expect(pid).To(Equal(42))
			Expect(cfg).To(Equal(kawasaki.NetworkConfig{
				ContainerIP:     net.ParseIP("10.255.1.2"),
				BridgeIP:        net.ParseIP("10.255.1.2"),
				ContainerHandle: "some-handle",
				DNSServers:      []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("9.9.9.9")},
			}))
		})

		Context("when the resolvConfigurer fails", func() {
			BeforeEach(func() {
				resolvConfigurer.ConfigureReturns(errors.New("banana"))
			})
			It("returns the error", func() {
				err := plugin.Network(logger, containerSpec, 42)

				Expect(err).To(MatchError("banana"))
			})
		})

		Context("when the external plugin errors", func() {
			BeforeEach(func() {
				pluginErr = errors.New("banana")
			})

			It("returns the error", func() {
				Expect(plugin.Network(logger, containerSpec, 42)).To(MatchError("external networker: banana"))
			})

			It("collects and logs the stderr from the plugin", func() {
				plugin.Network(logger, containerSpec, 42)
				Expect(logger).To(gbytes.Say("result.*error.*some-stderr-bytes"))
			})
		})

		Context("when the external plugin returns valid properties JSON", func() {
			It("persists the returned properties to the container's properties", func() {
				pluginOutput = `{"properties":{"foo":"bar","ping":"pong","garden.network.container-ip":"10.255.1.2"}}`

				err := plugin.Network(logger, containerSpec, 42)
				Expect(err).NotTo(HaveOccurred())

				persistedPropertyValue, _ := configStore.Get("some-handle", "foo")
				Expect(persistedPropertyValue).To(Equal("bar"))
			})
		})

		Context("when the external plugin returns invalid JSON", func() {
			It("returns a useful error message", func() {
				pluginOutput = "invalid-json"

				err := plugin.Network(logger, containerSpec, 42)
				Expect(err).To(MatchError(ContainSubstring("network plugin returned invalid JSON")))
			})
		})

		Context("when the external plugin returns JSON without a properties key", func() {
			It("returns a useful error message", func() {
				pluginOutput = `{"not-properties-key":{"foo":"bar"}}`

				err := plugin.Network(logger, containerSpec, 42)
				Expect(err).To(MatchError(ContainSubstring("network plugin returned JSON without a properties key")))
			})
		})
	})

	Describe("Destroy", func() {
		It("executes the external plugin with the correct args", func() {
			Expect(plugin.Destroy(logger, "my-handle")).To(Succeed())

			cmd := fakeCommandRunner.ExecutedCommands()[0]
			Expect(cmd.Path).To(Equal("some/path"))

			Expect(cmd.Args[:8]).To(Equal([]string{
				"some/path",
				"arg1",
				"arg2",
				"arg3",
				"--action", "down",
				"--handle", "my-handle",
			}))
		})

		Context("when the external plugin errors", func() {
			It("returns the error", func() {
				fakeCommandRunner.WhenRunning(fake_command_runner.CommandSpec{
					Path: "some/path",
				}, func(cmd *exec.Cmd) error {
					return errors.New("boom")
				})

				Expect(plugin.Destroy(logger, "my-handle")).To(MatchError("external networker: boom"))
			})
		})
	})

	Describe("NetIn", func() {
		var pluginOutput string
		var pluginErr error

		BeforeEach(func() {
			pluginErr = nil
			fakeCommandRunner.WhenRunning(fake_command_runner.CommandSpec{
				Path: "some/path",
			}, func(cmd *exec.Cmd) error {
				cmd.Stdout.Write([]byte(pluginOutput))
				cmd.Stderr.Write([]byte("some-stderr-bytes"))
				return pluginErr
			})
			pluginOutput = `{ "host_port": 22, "container_port": 33 }`
		})

		It("executes the external plugin with the correct args", func() {
			_, _, err := plugin.NetIn(logger, handle, 0, 33)
			Expect(err).NotTo(HaveOccurred())

			cmd := fakeCommandRunner.ExecutedCommands()[0]
			Expect(cmd.Path).To(Equal("some/path"))

			Expect(cmd.Args).To(Equal([]string{
				"some/path",
				"arg1",
				"arg2",
				"arg3",
				"--action", "net-in",
				"--handle", "some-handle",
				"--host-port", "0",
				"--container-port", "33",
			}))
		})

		It("returns the port pair returned by the plugin", func() {
			hostPort, containerPort, err := plugin.NetIn(logger, handle, 0, 33)
			Expect(err).NotTo(HaveOccurred())

			Expect(hostPort).To(Equal(uint32(22)))
			Expect(containerPort).To(Equal(uint32(33)))
		})

		It("adds a port mapping for the port pair returned by the plugin", func() {
			_, _, err := plugin.NetIn(logger, handle, 22, 33)
			Expect(err).NotTo(HaveOccurred())

			portMapping, ok := configStore.Get(handle, gardener.MappedPortsKey)
			Expect(ok).To(BeTrue())
			Expect(portMapping).To(MatchJSON(mustMarshalJSON([]garden.PortMapping{
				{
					HostPort:      22,
					ContainerPort: 33,
				},
			})))
		})

		Context("when the external plugin errors", func() {
			BeforeEach(func() {
				pluginErr = errors.New("boom")
			})

			It("returns the error", func() {
				_, _, err := plugin.NetIn(logger, handle, 22, 33)
				Expect(err).To(MatchError("external networker: boom"))
			})
		})

		Context("when adding the port mapping fails", func() {
			BeforeEach(func() {
				configStore.Set(handle, gardener.MappedPortsKey, "%%%%%%")
			})
			It("returns the error", func() {
				_, _, err := plugin.NetIn(logger, handle, 123, 543)
				Expect(err).To(MatchError(ContainSubstring("invalid character")))
			})
		})
	})

	Describe("NetOut", func() {
		handle := "my-handle"

		It("writes to the config store", func() {
			netOutRules := []garden.NetOutRule{{
				Protocol: garden.ProtocolTCP,
				Networks: []garden.IPRange{{
					Start: net.IPv4(10, 10, 10, 2),
					End:   net.IPv4(10, 10, 10, 2),
				}},
			}}

			expectedJSON, err := json.Marshal(netOutRules)
			Expect(err).NotTo(HaveOccurred())
			Expect(plugin.NetOut(logger, handle, netOutRules[0])).To(Succeed())
			v, ok := configStore.Get(handle, netplugin.NetOutKey)
			Expect(ok).To(BeTrue())
			Expect(v).To(MatchJSON(expectedJSON))
		})

		Context("when config store has existing net-out rule", func() {
			var oldNetOutRule garden.NetOutRule

			BeforeEach(func() {
				oldNetOutRule = garden.NetOutRule{
					Protocol: garden.ProtocolTCP,
					Networks: []garden.IPRange{{
						Start: net.IPv4(10, 10, 10, 2),
						End:   net.IPv4(10, 10, 10, 2),
					}},
				}

				netOutRules := []garden.NetOutRule{oldNetOutRule}
				r, _ := json.Marshal(netOutRules)
				configStore.Set(handle, netplugin.NetOutKey, string(r))
			})

			It("adds another net-out rule", func() {
				newNetOutRule := garden.NetOutRule{
					Protocol: garden.ProtocolTCP,
					Networks: []garden.IPRange{{
						Start: net.IPv4(10, 10, 10, 3),
						End:   net.IPv4(10, 10, 10, 3),
					}},
				}
				Expect(plugin.NetOut(logger, handle, newNetOutRule)).To(Succeed())

				expectedJSON, err := json.Marshal([]garden.NetOutRule{oldNetOutRule, newNetOutRule})
				Expect(err).NotTo(HaveOccurred())
				v, ok := configStore.Get(handle, netplugin.NetOutKey)
				Expect(ok).To(BeTrue())
				Expect(v).To(MatchJSON(expectedJSON))
			})
		})

		Context("when config store has bad net-out rule data", func() {
			BeforeEach(func() {
				configStore.Set(handle, netplugin.NetOutKey, "bad-data")
			})

			It("returns an error", func() {
				newNetOutRule := garden.NetOutRule{
					Protocol: garden.ProtocolTCP,
					Networks: []garden.IPRange{{
						Start: net.IPv4(10, 10, 10, 3),
						End:   net.IPv4(10, 10, 10, 3),
					}},
				}
				err := plugin.NetOut(logger, handle, newNetOutRule)
				Expect(err).To(MatchError(ContainSubstring("store net-out invalid JSON")))
			})
		})
	})
})
