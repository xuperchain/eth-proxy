/*
 * Copyright (c) 2021. Baidu Inc. All Rights Reserved.
 */

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/xuperchain/eth_proxy"
)

var host string
var port int
var account string
var keyPath string

// InitFlags sets up the flags and environment variables for Proxy
//func initFlags() {
//}

// Viper takes care of precedence of Flags and Environment variables
// Flag values are taken over environment variables
// Both CCID and Port have defaults so do not need to be provided.
//func checkFlags() error {
//	host = viper.GetString("host")
//	if host == "" {
//		return fmt.Errorf("Missing host. Please use flag --host or set PROXY_HOST")
//	}
//
//	port = viper.GetInt("port")
//	return nil
//}

// Runs Proxy
// Will exit gracefully for errors and signal interrupts
func runProxy(cmd *cobra.Command, args []string) error {

	rawLogger, err := zap.NewDevelopment()
	if err != nil {
		return fmt.Errorf("Failed to create logger: %s\n", err)
	}
	logger := rawLogger.Named("proxy").Sugar()

	ethService, err := eth_proxy.NewEthService(&eth_proxy.EthServiceConfig{
		Host:            host,
		ContractAccount: account,
		KeyPath:         keyPath,
	})
	if err != nil {
		return err
	}

	proxy := eth_proxy.NewEthereumProxy(ethService, port)

	errChan := make(chan error, 1)
	go func() {
		errChan <- proxy.Start()
	}()
	logger.Infow("Starting Proxy", "port", port)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	select {
	case err = <-errChan:
		fmt.Println(err)
		// TODO add error check
	case <-signalChan:
		logger.Info("Received termination signal")
		err = proxy.Shutdown()
	}

	if err != nil {
		logger.Infow("Proxy exited with error", "error", err)
		return err
	}
	logger.Info("Proxy exited")
	return nil
}

func main() {
	var proxyCmd = &cobra.Command{
		Use:   "proxy",
		Short: "proxy is a web3 provider used to interact with the EVM chaincode on a XuperChain Network. The flags provided will be honored over the corresponding environment variables.",
		Long:  "proxy is a web3 provider used to interact with the EVM chaincode on a XuperChain Network. The flags provided will be honored over the corresponding environment variables.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {

			// At this point all of our flags have been validated
			// Usage no longer needs to be provided for the errors that follow
			cmd.SilenceUsage = false
			return runProxy(cmd, args)
		},
	}
	viper.SetEnvPrefix("PROXY")
	viper.BindEnv("host")
	viper.BindEnv("port")
	viper.BindEnv("account")

	proxyCmd.PersistentFlags().StringVarP(&host, "host", "t", "127.0.0.1:37101",
		"Path to a compatible Fabric SDK Go config file. This flag is required if PROXY_HOST is not set.")
	viper.BindPFlag("config", proxyCmd.PersistentFlags().Lookup("host"))

	proxyCmd.PersistentFlags().IntVarP(&port, "port", "p", 8545,
		"Port that Proxy will be running on. The listening port can also be set by the PROXY_PORT environment variable.")
	viper.BindPFlag("port", proxyCmd.PersistentFlags().Lookup("port"))

	proxyCmd.PersistentFlags().StringVar(&account, "account", "XC1234567890123456@xuper", "account to send transaction")
	viper.BindPFlag("account", proxyCmd.PersistentFlags().Lookup("account"))

	proxyCmd.PersistentFlags().StringVar(&keyPath, "key", "data/keys", "key path")
	viper.BindPFlag("key", proxyCmd.PersistentFlags().Lookup("key"))

	if proxyCmd.Execute() != nil {
		os.Exit(1)
	}
}
