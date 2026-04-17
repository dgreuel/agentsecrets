package commands

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/api/offline"
	"github.com/The-17/agentsecrets/pkg/auth"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/ui"
	"github.com/The-17/agentsecrets/pkg/workspaces"
)

// Version is set at build time via ldflags
var Version = "dev"

var (
	authService      *auth.Service
	workspaceService *workspaces.Service
	apiClient        api.Backend
	apiURL           string // Global flag: --api-url (highest precedence)
	offlineFlag      bool   // Global flag: --offline (forces in-process backend)
)

// rootCmd is the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "agentsecrets",
	Short: "Secure secrets management for the AI era",
	Long: lipgloss.JoinVertical(lipgloss.Left,
		"",
		ui.BrandStyle.Render("AgentSecrets"),
		ui.DimStyle.Render("   Zero-knowledge secrets manager for AI-assisted development"),
		"",
		ui.LabelStyle.Render("   Manage secrets across projects, teams, and environments."),
		ui.LabelStyle.Render("   AI assistants can use this tool without seeing secret values."),
		"",
		ui.DimStyle.Render("   Get started:"),
		"   "+ui.BrandStyle.Render("agentsecrets init")+"        "+ui.LabelStyle.Render("Create a new account"),
		"   "+ui.BrandStyle.Render("agentsecrets login")+"       "+ui.LabelStyle.Render("Login to existing account"),
		"   "+ui.BrandStyle.Render("agentsecrets status")+"      "+ui.LabelStyle.Render("Show current session info"),
		"",
	),
	Version: Version,
}

func Execute() error {
	// Run update check. It's efficient (24h interval) and has a short timeout.
	if res, _ := config.CheckForUpdates(Version); res != nil && res.NewVersionAvailable {
		ui.Banner(fmt.Sprintf("Update Available: %s → %s", res.CurrentVersion, res.LatestVersion))
		ui.Info("Run 'brew upgrade agentsecrets', 'npm install -g @the-17/agentsecrets',")
		ui.Info("or 'pip install agentsecrets-cli' to update.")
		ui.Divider()
		fmt.Println()
	}

	return rootCmd.Execute()
}

func init() {
	// Add global flags
	rootCmd.PersistentFlags().StringVar(&apiURL, "api-url", "", "API base URL (overrides AGENTSECRETS_API_URL and config)")
	rootCmd.PersistentFlags().BoolVar(&offlineFlag, "offline", false, "Run with the in-process SQLite backend (no network)")

	// The flag value isn't bound until Cobra parses argv, but several callers
	// (init() bodies in subcommand files, the global services below) resolve
	// the mode immediately. Sniff os.Args directly so we get the right answer
	// before Cobra runs.
	for _, a := range os.Args[1:] {
		if a == "--offline" {
			config.SetModeOverride(config.ModeOffline)
			offlineFlag = true
			break
		}
	}

	// Build the backend. Offline → in-process SQLite. Online → HTTP client.
	if config.ResolveMode() == config.ModeOffline {
		be, err := offline.New("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentsecrets: failed to open offline backend: %v\n", err)
			os.Exit(1)
		}
		apiClient = be
	} else {
		// Resolve API URL with precedence: CLI flag > env var > config > default
		resolvedURL := apiURL // CLI flag has highest precedence
		if resolvedURL == "" {
			resolvedURL = config.ResolveAPIBaseURL()
		}

		client := api.NewClient(func() string {
			return config.GetAccessToken()
		})
		client.BaseURL = resolvedURL
		apiClient = client
	}

	// Inject the stored 1Password service account token before any op CLI call.
	// Only done when the env var isn't already present so explicit env vars win.
	if os.Getenv("OP_SERVICE_ACCOUNT_TOKEN") == "" {
		if token, err := keyring.GetOPToken(); err == nil && token != "" {
			os.Setenv("OP_SERVICE_ACCOUNT_TOKEN", token)
		}
	}

	// Enable 1Password backend if storage mode 3 is configured.
	if config.GetStorageMode() == 3 {
		keyring.Configure1Password(config.GetOnePasswordVault())
	}

	// Create the shared services
	authService = auth.NewService(apiClient)
	workspaceService = workspaces.NewService(apiClient)
	InitProjectService(apiClient)
	InitSecretsService(apiClient)

	// Register all subcommands
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(statusCmd)

	// Add auth middleware to commands that require it
	workspaceCmd.PersistentPreRunE = authService.EnsureAuth
	projectCmd.PersistentPreRunE = authService.EnsureAuth
	secretsCmd.PersistentPreRunE = authService.EnsureAuth
	callCmd.PersistentPreRunE = authService.EnsureAuth
	environmentCmd.PersistentPreRunE = authService.EnsureAuth

	rootCmd.AddCommand(workspaceCmd)
	rootCmd.AddCommand(projectCmd)
	rootCmd.AddCommand(secretsCmd)
	rootCmd.AddCommand(agentCmd)
	rootCmd.AddCommand(logCmd)
	rootCmd.AddCommand(proxyCmd)
	rootCmd.AddCommand(mcpCmd)
	rootCmd.AddCommand(callCmd)
	rootCmd.AddCommand(environmentCmd)
	rootCmd.AddCommand(NewEnvCmd())
	rootCmd.AddCommand(NewExecCmd())
	rootCmd.AddCommand(opCmd)
}
