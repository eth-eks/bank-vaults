// Copyright © 2018 Banzai Cloud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/bank-vaults/vault-sdk/vault"
	"github.com/spf13/cobra"

	"strings"

	internalVault "github.com/bank-vaults/bank-vaults/internal/vault"
)

const (
	cfgRekeyRetryPeriod = "init"
	cfgPgpKeys          = "pgp-keys"
)

type rekeyCfg struct {
	rekeyRetryPeriod time.Duration
	pgpKeys          string
}

var rekeyCmd = &cobra.Command{
	Use:   "rekey",
	Short: "Rekeying Vault using Keybase PGP keys.",
	Long: `It will continuously attempt to rekey the target Vault instance, by retrieving unseal keys
from one of the following:
- Google Cloud KMS keyring (backed by GCS)
- AWS KMS keyring (backed by S3)
- Azure Key Vault
- Alibaba KMS (backed by OSS)
- Kubernetes Secrets (should be used only for development purposes)
Resulting keys will be encrypted by Keybase PGP`,
	Run: func(cmd *cobra.Command, args []string) {
		var rekeyConfig rekeyCfg

		rekeyConfig.rekeyRetryPeriod = c.GetDuration(cfgRekeyRetryPeriod)
		rekeyConfig.pgpKeys = c.GetString(cfgPgpKeys)

		store, err := kvStoreForConfig(c)
		if err != nil {
			slog.Error(fmt.Sprintf("error creating kv store: %s", err.Error()))
			os.Exit(1)
		}

		cl, err := vault.NewRawClient()
		if err != nil {
			slog.Error(fmt.Sprintf("error connecting to vault: %s", err.Error()))
			os.Exit(1)
		}

		v, err := internalVault.New(store, cl, vaultConfigForConfig(c))
		if err != nil {
			slog.Error(fmt.Sprintf("error creating vault helper: %s", err.Error()))
			os.Exit(1)
		}

		for {
			if newKeysNotExists(rekeyConfig, v) {
				rekey(rekeyConfig, v)
			}
			// wait retryPerios before trying again
			time.Sleep(rekeyConfig.rekeyRetryPeriod)
		}
	},
}

func newKeysNotExists(rekeyConfig rekeyCfg, v internalVault.Vault) bool {
	slog.Debug("checking if unseal keys already exist...")
	exists, err := v.NewUnsealKeysExists(strings.Split(rekeyConfig.pgpKeys, ","))
	if err != nil {
		slog.Error(fmt.Sprintf("error checking if unseal keys already exist: %s", err.Error()))
		os.Exit(1)
	}
	return !exists
}

func rekey(rekeyConfig rekeyCfg, v internalVault.Vault) {
	slog.Debug("checking if vault is sealed...")
	sealed, err := v.Sealed()
	if err != nil {
		slog.Error(fmt.Sprintf("error checking if vault is sealed: %s", err.Error()))
		os.Exit(1)
		return
	}

	if !sealed {
		slog.Debug("vault is not sealed, rekeying")

		if err = v.Rekey(strings.Split(rekeyConfig.pgpKeys, ",")); err != nil {
			slog.Error(fmt.Sprintf("error rekeying vault: %s", err.Error()))
			os.Exit(1)
			return
		}
		slog.Info("successfully rekeyed vault")
	}
}

func init() {
	configStringVar(rekeyCmd, cfgPgpKeys, "", "Coma separated list of pgp keys")
	configDurationVar(rekeyCmd, cfgRekeyRetryPeriod, 10*time.Second, "Retry period for rekeying")
	rootCmd.AddCommand(rekeyCmd)
}
