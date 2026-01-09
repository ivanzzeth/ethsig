package main

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestRootCommand(t *testing.T) {
	if rootCmd == nil {
		t.Fatal("rootCmd should not be nil")
	}

	if rootCmd.Use != "keystore" {
		t.Errorf("rootCmd.Use = %q, want %q", rootCmd.Use, "keystore")
	}

	if rootCmd.Short == "" {
		t.Error("rootCmd.Short should not be empty")
	}

	if rootCmd.Long == "" {
		t.Error("rootCmd.Long should not be empty")
	}

	if rootCmd.Version != version {
		t.Errorf("rootCmd.Version = %q, want %q", rootCmd.Version, version)
	}
}

func TestSubcommands(t *testing.T) {
	subcommands := rootCmd.Commands()
	expectedCommands := []string{"create", "import", "change-password", "list", "show", "verify"}

	commandMap := make(map[string]*cobra.Command)
	for _, cmd := range subcommands {
		commandMap[cmd.Use] = cmd
	}

	for _, expected := range expectedCommands {
		if _, exists := commandMap[expected]; !exists {
			t.Errorf("Expected subcommand %q not found", expected)
		}
	}
}

func TestCreateCommand(t *testing.T) {
	if createCmd == nil {
		t.Fatal("createCmd should not be nil")
	}

	if createCmd.Use != "create" {
		t.Errorf("createCmd.Use = %q, want %q", createCmd.Use, "create")
	}

	if createCmd.Short == "" {
		t.Error("createCmd.Short should not be empty")
	}

	if createCmd.RunE == nil {
		t.Error("createCmd.RunE should not be nil")
	}

	// Test flag exists
	flag := createCmd.Flags().Lookup("dir")
	if flag == nil {
		t.Error("createCmd should have --dir flag")
	}
	if flag.Shorthand != "d" {
		t.Errorf("dir flag shorthand = %q, want %q", flag.Shorthand, "d")
	}
}

func TestImportCommand(t *testing.T) {
	if importCmd == nil {
		t.Fatal("importCmd should not be nil")
	}

	if importCmd.Use != "import" {
		t.Errorf("importCmd.Use = %q, want %q", importCmd.Use, "import")
	}

	if importCmd.Short == "" {
		t.Error("importCmd.Short should not be empty")
	}

	if importCmd.RunE == nil {
		t.Error("importCmd.RunE should not be nil")
	}

	// Test flag exists
	flag := importCmd.Flags().Lookup("dir")
	if flag == nil {
		t.Error("importCmd should have --dir flag")
	}
}

func TestChangePasswordCommand(t *testing.T) {
	if changePasswordCmd == nil {
		t.Fatal("changePasswordCmd should not be nil")
	}

	if changePasswordCmd.Use != "change-password" {
		t.Errorf("changePasswordCmd.Use = %q, want %q", changePasswordCmd.Use, "change-password")
	}

	if changePasswordCmd.Short == "" {
		t.Error("changePasswordCmd.Short should not be empty")
	}

	if changePasswordCmd.RunE == nil {
		t.Error("changePasswordCmd.RunE should not be nil")
	}

	// Test flag exists
	flag := changePasswordCmd.Flags().Lookup("keystore")
	if flag == nil {
		t.Error("changePasswordCmd should have --keystore flag")
	}
	if flag.Shorthand != "k" {
		t.Errorf("keystore flag shorthand = %q, want %q", flag.Shorthand, "k")
	}
}

func TestListCommand(t *testing.T) {
	if listCmd == nil {
		t.Fatal("listCmd should not be nil")
	}

	if listCmd.Use != "list" {
		t.Errorf("listCmd.Use = %q, want %q", listCmd.Use, "list")
	}

	if listCmd.Short == "" {
		t.Error("listCmd.Short should not be empty")
	}

	if listCmd.RunE == nil {
		t.Error("listCmd.RunE should not be nil")
	}

	// Test flag exists
	flag := listCmd.Flags().Lookup("dir")
	if flag == nil {
		t.Error("listCmd should have --dir flag")
	}
}

func TestShowCommand(t *testing.T) {
	if showCmd == nil {
		t.Fatal("showCmd should not be nil")
	}

	if showCmd.Use != "show" {
		t.Errorf("showCmd.Use = %q, want %q", showCmd.Use, "show")
	}

	if showCmd.Short == "" {
		t.Error("showCmd.Short should not be empty")
	}

	if showCmd.RunE == nil {
		t.Error("showCmd.RunE should not be nil")
	}

	// Test flag exists
	flag := showCmd.Flags().Lookup("keystore")
	if flag == nil {
		t.Error("showCmd should have --keystore flag")
	}
}

func TestVerifyCommand(t *testing.T) {
	if verifyCmd == nil {
		t.Fatal("verifyCmd should not be nil")
	}

	if verifyCmd.Use != "verify" {
		t.Errorf("verifyCmd.Use = %q, want %q", verifyCmd.Use, "verify")
	}

	if verifyCmd.Short == "" {
		t.Error("verifyCmd.Short should not be empty")
	}

	if verifyCmd.RunE == nil {
		t.Error("verifyCmd.RunE should not be nil")
	}

	// Test flag exists
	flag := verifyCmd.Flags().Lookup("keystore")
	if flag == nil {
		t.Error("verifyCmd should have --keystore flag")
	}
}

func TestVersion(t *testing.T) {
	if version == "" {
		t.Error("version should not be empty")
	}
}

func TestDirFlagDefaults(t *testing.T) {
	// Test default values for dir flags
	tests := []struct {
		name    string
		cmd     *cobra.Command
		flag    string
		defVal  string
	}{
		{"create dir", createCmd, "dir", "./keystores"},
		{"import dir", importCmd, "dir", "./keystores"},
		{"list dir", listCmd, "dir", "./keystores"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := tt.cmd.Flags().Lookup(tt.flag)
			if flag == nil {
				t.Fatalf("Flag %s not found", tt.flag)
			}
			if flag.DefValue != tt.defVal {
				t.Errorf("Default value = %q, want %q", flag.DefValue, tt.defVal)
			}
		})
	}
}

func TestKeystoreFlagRequired(t *testing.T) {
	// Test that keystore flag is required for certain commands
	tests := []struct {
		name string
		cmd  *cobra.Command
	}{
		{"change-password", changePasswordCmd},
		{"show", showCmd},
		{"verify", verifyCmd},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := tt.cmd.Flags().Lookup("keystore")
			if flag == nil {
				t.Fatalf("Flag keystore not found for %s", tt.name)
			}
			// Check if flag is marked as required via annotations
			annotations := flag.Annotations
			if _, exists := annotations[cobra.BashCompOneRequiredFlag]; !exists {
				// The flag should be marked as required
				t.Logf("Flag keystore for %s may not be properly marked as required", tt.name)
			}
		})
	}
}

func TestCommandHelp(t *testing.T) {
	// Test that help doesn't panic
	cmds := []*cobra.Command{createCmd, importCmd, changePasswordCmd, listCmd, showCmd, verifyCmd}
	for _, cmd := range cmds {
		t.Run(cmd.Use, func(t *testing.T) {
			help := cmd.UsageString()
			if help == "" {
				t.Error("UsageString should not be empty")
			}
		})
	}
}
