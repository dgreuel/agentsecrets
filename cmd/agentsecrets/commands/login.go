package commands

import (
	"fmt"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/ui"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to your AgentSecrets account",
	Long: `Login to your existing AgentSecrets account.

	This will:
	1. Prompt for your email and password
	2. Authenticate with the server
	3. Decrypt your private key using your password
	4. Download and decrypt your workspace keys
	5. Cache credentials locally for future commands`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return performLogin()
	},
}

// performLogin collects credentials and logs in. Shared by login command and init flow.
func performLogin() error {
	var (
		email    string
		password string
	)

	isOffline := config.IsOfflineMode()

	var fields []huh.Field
	if !isOffline {
		fields = append(fields, huh.NewInput().
			Title("Email").
			Value(&email).
			Validate(func(s string) error {
				if s == "" {
					return fmt.Errorf("email is required")
				}
				return nil
			}))
	} else {
		email = offlineLocalEmail()
	}

	fields = append(fields, huh.NewInput().
		Title("Password").
		EchoMode(huh.EchoModePassword).
		Value(&password).
		Validate(func(s string) error {
			if s == "" {
				return fmt.Errorf("password is required")
			}
			return nil
		}))

	form := huh.NewForm(
		huh.NewGroup(fields...),
	)

	if err := form.Run(); err != nil {
		return nil
	}

	fmt.Println()

	actionStr := "Logging in..."
	successStr := "Logged in successfully!"
	failStr := "Login failed"
	if isOffline {
		actionStr = "Unlocking..."
		successStr = "Unlocked successfully!"
		failStr = "Unlock failed"
	}

	if err := ui.Spinner(actionStr, func() error {
		return authService.PerformLogin(email, password, nil, nil)
	}); err != nil {
		ui.Error(failStr + ": " + err.Error())
		return nil
	}

	fmt.Println()
	ui.Success(successStr)
	return nil
}
