package commands

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/The-17/agentsecrets/pkg/backends/onepassword"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var opCmd = &cobra.Command{
	Use:   "1password",
	Short: "Configure 1Password as the local secrets backend",
	Long: `Manage the 1Password integration for AgentSecrets.

When 1Password is active (storage mode 3), decrypted secrets are stored as
Password items in your chosen 1Password vault instead of the OS keychain.
The AgentSecrets cloud API remains the authoritative encrypted store; 1Password
acts as the local cache that the proxy, MCP server, and env injection read from.

Authentication is handled entirely by the op CLI — no credentials are stored
by AgentSecrets. Interactive sessions use biometric/system auth; headless and
CI environments use the OP_SERVICE_ACCOUNT_TOKEN environment variable.`,
}

var opSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive wizard to configure 1Password as the secrets backend",
	RunE:  runOPSetup,
}

var opVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Check that the 1Password CLI is installed, signed in, and the vault is reachable",
	RunE:  runOPVerify,
}

var opTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage the stored 1Password service account token",
	Long: `Store or remove a 1Password service account token in the OS keychain.

When a token is stored, AgentSecrets automatically sets OP_SERVICE_ACCOUNT_TOKEN
before calling the op CLI, so you don't need to keep it in your shell environment.
This is most useful for CI-free interactive setups where you want unattended access
without adding the token to .zshrc / .bashrc.`,
}

var opTokenSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Save a 1Password service account token to the OS keychain",
	RunE:  runOPTokenSet,
}

var opTokenDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Remove the stored 1Password service account token from the OS keychain",
	RunE:  runOPTokenDelete,
}

func init() {
	opTokenCmd.AddCommand(opTokenSetCmd)
	opTokenCmd.AddCommand(opTokenDeleteCmd)
	opCmd.AddCommand(opSetupCmd)
	opCmd.AddCommand(opVerifyCmd)
	opCmd.AddCommand(opTokenCmd)
}

func runOPSetup(cmd *cobra.Command, args []string) error {
	// 1. Check op CLI is installed.
	if !onepassword.IsAvailable() {
		ui.Error("The 1Password CLI (op) is not installed.")
		fmt.Println()
		fmt.Println("  Install it from: https://1password.com/downloads/command-line/")
		fmt.Println("  macOS (Homebrew): brew install 1password-cli")
		fmt.Println("  Then run 'op signin' and re-run this command.")
		return fmt.Errorf("op CLI not found")
	}
	ui.Success("1Password CLI (op) found")

	// 2. Check sign-in.
	if err := onepassword.CheckSignedIn(); err != nil {
		ui.Error("Not signed in to 1Password.")
		fmt.Println()
		fmt.Println("  Run: op signin")
		fmt.Println("  Or set OP_SERVICE_ACCOUNT_TOKEN for headless/CI environments.")
		return err
	}
	ui.Success("Signed in to 1Password")

	// 3. List available vaults.
	vaults, err := onepassword.ListVaults()
	if err != nil {
		return fmt.Errorf("could not list vaults: %w", err)
	}
	if len(vaults) == 0 {
		return fmt.Errorf("no accessible vaults found in your 1Password account")
	}

	// 4. Prompt for vault selection.
	currentVault := config.GetOnePasswordVault()

	// Build huh options from the real vault list; prepend "AgentSecrets (create new)" if missing.
	var options []huh.Option[string]
	hasAgentSecrets := false
	for _, v := range vaults {
		if v == "AgentSecrets" {
			hasAgentSecrets = true
		}
		label := v
		if v == currentVault {
			label = v + " (current)"
		}
		options = append(options, huh.NewOption(label, v))
	}
	if !hasAgentSecrets {
		options = append([]huh.Option[string]{
			huh.NewOption("AgentSecrets (will be created)", "AgentSecrets"),
		}, options...)
	}

	var selectedVault string
	err = huh.NewSelect[string]().
		Title("Which 1Password vault should AgentSecrets use?").
		Description("Secrets will be stored as Password items inside this vault.").
		Options(options...).
		Value(&selectedVault).
		Run()
	if err != nil {
		return nil // user cancelled
	}

	// 5. Verify write access before committing to this vault.
	ui.Info(fmt.Sprintf("Checking write access to %q...", selectedVault))
	testClient := onepassword.NewClient(selectedVault)
	if err := testClient.CheckVaultWritable(); err != nil {
		fmt.Println()
		ui.Error("Cannot write to that vault:")
		fmt.Println("  " + err.Error())
		fmt.Println()
		fmt.Println("  To create a vault you own:")
		fmt.Println("    op vault create \"AgentSecrets\"")
		fmt.Println("  Then re-run: agentsecrets 1password setup")
		return fmt.Errorf("vault not writable")
	}
	ui.Success(fmt.Sprintf("Write access confirmed for %q", selectedVault))

	// 6. Persist the vault choice and enable mode 3.
	if err := config.SetOnePasswordVault(selectedVault); err != nil {
		return fmt.Errorf("save vault: %w", err)
	}
	if err := config.SetStorageMode(3); err != nil {
		return fmt.Errorf("set storage mode: %w", err)
	}
	// Also update project-level config: GetStorageMode() checks project.json before
	// the global config, so without this the project setting (1) always wins.
	_ = config.SetProjectStorageMode(3)

	// 6. Wire the backend for this process so verify works immediately.
	keyring.Configure1Password(selectedVault)

	fmt.Println()
	ui.Success(fmt.Sprintf("1Password backend enabled (vault: %s)", selectedVault))
	ui.Info("Storage mode set to 3 (1Password).")
	fmt.Println()
	ui.Info("Next steps:")
	fmt.Println("  agentsecrets secrets pull   — sync secrets from cloud → 1Password")
	fmt.Println("  agentsecrets 1password verify — confirm the integration is working")

	return nil
}

func runOPVerify(cmd *cobra.Command, args []string) error {
	allOK := true

	// op CLI installed?
	if !onepassword.IsAvailable() {
		ui.StatusRow("op CLI", "NOT FOUND — install from https://1password.com/downloads/command-line/")
		allOK = false
	} else {
		ui.StatusRow("op CLI", "installed")
	}

	// Signed in?
	if err := onepassword.CheckSignedIn(); err != nil {
		ui.StatusRow("Signed in", "NO — run 'op signin' or set OP_SERVICE_ACCOUNT_TOKEN")
		allOK = false
	} else {
		ui.StatusRow("Signed in", "yes")
	}

	// Vault accessible?
	vault := config.GetOnePasswordVault()
	vaults, err := onepassword.ListVaults()
	if err != nil {
		ui.StatusRow("Vault", fmt.Sprintf("error listing vaults: %v", err))
		allOK = false
	} else {
		found := false
		for _, v := range vaults {
			if v == vault {
				found = true
				break
			}
		}
		if found {
			ui.StatusRow("Vault", fmt.Sprintf("%q accessible", vault))
		} else {
			ui.StatusRow("Vault", fmt.Sprintf("%q NOT found — run 'agentsecrets 1password setup'", vault))
			allOK = false
		}
	}

	// Storage mode
	mode := config.GetStorageMode()
	if mode == 3 {
		ui.StatusRow("Storage mode", "3 (1Password) ✓")
	} else {
		ui.StatusRow("Storage mode", fmt.Sprintf("%d — run 'agentsecrets 1password setup' to switch to mode 3", mode))
		allOK = false
	}

	// Stored token
	if _, err := keyring.GetOPToken(); err == nil {
		ui.StatusRow("Saved token", "present in OS keychain (auto-injected as OP_SERVICE_ACCOUNT_TOKEN)")
	} else {
		ui.StatusRow("Saved token", "none — use 'agentsecrets 1password token set' to save one")
	}

	fmt.Println()
	if allOK {
		ui.Success("1Password integration is correctly configured.")
	} else {
		ui.Error("One or more checks failed. See details above.")
		return fmt.Errorf("verification failed")
	}
	return nil
}

func runOPTokenSet(cmd *cobra.Command, args []string) error {
	// Prompt for the token without echoing it to the terminal.
	// We use golang.org/x/term directly because huh's EchoModePassword still
	// echoes bullet characters, which is fine for passwords but leaky for tokens.
	fmt.Print("1Password service account token: ")
	raw, err := term.ReadPassword(0)
	fmt.Println()
	if err != nil {
		return fmt.Errorf("read token: %w", err)
	}

	token := strings.TrimSpace(string(raw))
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if err := keyring.StoreOPToken(token); err != nil {
		return fmt.Errorf("store token: %w", err)
	}

	ui.Success("Service account token saved to OS keychain.")
	ui.Info("AgentSecrets will automatically set OP_SERVICE_ACCOUNT_TOKEN on each run.")
	return nil
}

func runOPTokenDelete(cmd *cobra.Command, args []string) error {
	if err := keyring.DeleteOPToken(); err != nil {
		return fmt.Errorf("delete token: %w", err)
	}
	ui.Success("Service account token removed from OS keychain.")
	return nil
}
