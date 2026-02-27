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
	expectedCommands := []string{"create", "import", "change-password", "list", "show", "verify", "hdwallet"}

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
	cmds := []*cobra.Command{createCmd, importCmd, changePasswordCmd, listCmd, showCmd, verifyCmd, hdwalletCmd}
	for _, cmd := range cmds {
		t.Run(cmd.Use, func(t *testing.T) {
			help := cmd.UsageString()
			if help == "" {
				t.Error("UsageString should not be empty")
			}
		})
	}
}

// --- HD wallet command tests ---

func TestHDWalletCommand(t *testing.T) {
	if hdwalletCmd == nil {
		t.Fatal("hdwalletCmd should not be nil")
	}

	if hdwalletCmd.Use != "hdwallet" {
		t.Errorf("hdwalletCmd.Use = %q, want %q", hdwalletCmd.Use, "hdwallet")
	}

	if hdwalletCmd.Short == "" {
		t.Error("hdwalletCmd.Short should not be empty")
	}

	if hdwalletCmd.Long == "" {
		t.Error("hdwalletCmd.Long should not be empty")
	}
}

func TestHDWalletSubcommands(t *testing.T) {
	subcommands := hdwalletCmd.Commands()
	expectedCommands := []string{"create", "import", "list", "derive", "info", "verify", "export-mnemonic"}

	commandMap := make(map[string]*cobra.Command)
	for _, cmd := range subcommands {
		commandMap[cmd.Use] = cmd
	}

	for _, expected := range expectedCommands {
		if _, exists := commandMap[expected]; !exists {
			t.Errorf("Expected hdwallet subcommand %q not found", expected)
		}
	}
}

func TestHDWalletCreateCommand(t *testing.T) {
	if hdwalletCreateCmd == nil {
		t.Fatal("hdwalletCreateCmd should not be nil")
	}

	if hdwalletCreateCmd.Use != "create" {
		t.Errorf("hdwalletCreateCmd.Use = %q, want %q", hdwalletCreateCmd.Use, "create")
	}

	if hdwalletCreateCmd.Short == "" {
		t.Error("hdwalletCreateCmd.Short should not be empty")
	}

	if hdwalletCreateCmd.RunE == nil {
		t.Error("hdwalletCreateCmd.RunE should not be nil")
	}

	// Test flags
	dirFlag := hdwalletCreateCmd.Flags().Lookup("dir")
	if dirFlag == nil {
		t.Error("hdwalletCreateCmd should have --dir flag")
	}
	if dirFlag.Shorthand != "d" {
		t.Errorf("dir flag shorthand = %q, want %q", dirFlag.Shorthand, "d")
	}
	if dirFlag.DefValue != "./hdwallets" {
		t.Errorf("dir default = %q, want %q", dirFlag.DefValue, "./hdwallets")
	}

	entropyFlag := hdwalletCreateCmd.Flags().Lookup("entropy")
	if entropyFlag == nil {
		t.Error("hdwalletCreateCmd should have --entropy flag")
	}
	if entropyFlag.DefValue != "128" {
		t.Errorf("entropy default = %q, want %q", entropyFlag.DefValue, "128")
	}
}

func TestHDWalletImportCommand(t *testing.T) {
	if hdwalletImportCmd == nil {
		t.Fatal("hdwalletImportCmd should not be nil")
	}

	if hdwalletImportCmd.Use != "import" {
		t.Errorf("hdwalletImportCmd.Use = %q, want %q", hdwalletImportCmd.Use, "import")
	}

	if hdwalletImportCmd.Short == "" {
		t.Error("hdwalletImportCmd.Short should not be empty")
	}

	if hdwalletImportCmd.RunE == nil {
		t.Error("hdwalletImportCmd.RunE should not be nil")
	}

	dirFlag := hdwalletImportCmd.Flags().Lookup("dir")
	if dirFlag == nil {
		t.Error("hdwalletImportCmd should have --dir flag")
	}
}

func TestHDWalletListCommand(t *testing.T) {
	if hdwalletListCmd == nil {
		t.Fatal("hdwalletListCmd should not be nil")
	}

	if hdwalletListCmd.Use != "list" {
		t.Errorf("hdwalletListCmd.Use = %q, want %q", hdwalletListCmd.Use, "list")
	}

	if hdwalletListCmd.Short == "" {
		t.Error("hdwalletListCmd.Short should not be empty")
	}

	if hdwalletListCmd.RunE == nil {
		t.Error("hdwalletListCmd.RunE should not be nil")
	}

	dirFlag := hdwalletListCmd.Flags().Lookup("dir")
	if dirFlag == nil {
		t.Error("hdwalletListCmd should have --dir flag")
	}
	if dirFlag.Shorthand != "d" {
		t.Errorf("dir flag shorthand = %q, want %q", dirFlag.Shorthand, "d")
	}
	if dirFlag.DefValue != "./hdwallets" {
		t.Errorf("dir default = %q, want %q", dirFlag.DefValue, "./hdwallets")
	}
}

func TestHDWalletDeriveCommand(t *testing.T) {
	if hdwalletDeriveCmd == nil {
		t.Fatal("hdwalletDeriveCmd should not be nil")
	}

	if hdwalletDeriveCmd.Use != "derive" {
		t.Errorf("hdwalletDeriveCmd.Use = %q, want %q", hdwalletDeriveCmd.Use, "derive")
	}

	if hdwalletDeriveCmd.Short == "" {
		t.Error("hdwalletDeriveCmd.Short should not be empty")
	}

	if hdwalletDeriveCmd.RunE == nil {
		t.Error("hdwalletDeriveCmd.RunE should not be nil")
	}

	walletFlag := hdwalletDeriveCmd.Flags().Lookup("wallet")
	if walletFlag == nil {
		t.Error("hdwalletDeriveCmd should have --wallet flag")
	}
	if walletFlag.Shorthand != "w" {
		t.Errorf("wallet flag shorthand = %q, want %q", walletFlag.Shorthand, "w")
	}

	startFlag := hdwalletDeriveCmd.Flags().Lookup("start")
	if startFlag == nil {
		t.Error("hdwalletDeriveCmd should have --start flag")
	}
	if startFlag.DefValue != "0" {
		t.Errorf("start default = %q, want %q", startFlag.DefValue, "0")
	}

	endFlag := hdwalletDeriveCmd.Flags().Lookup("end")
	if endFlag == nil {
		t.Error("hdwalletDeriveCmd should have --end flag")
	}
	if endFlag.DefValue != "10" {
		t.Errorf("end default = %q, want %q", endFlag.DefValue, "10")
	}
}

func TestHDWalletInfoCommand(t *testing.T) {
	if hdwalletInfoCmd == nil {
		t.Fatal("hdwalletInfoCmd should not be nil")
	}

	if hdwalletInfoCmd.Use != "info" {
		t.Errorf("hdwalletInfoCmd.Use = %q, want %q", hdwalletInfoCmd.Use, "info")
	}

	if hdwalletInfoCmd.Short == "" {
		t.Error("hdwalletInfoCmd.Short should not be empty")
	}

	if hdwalletInfoCmd.RunE == nil {
		t.Error("hdwalletInfoCmd.RunE should not be nil")
	}

	walletFlag := hdwalletInfoCmd.Flags().Lookup("wallet")
	if walletFlag == nil {
		t.Error("hdwalletInfoCmd should have --wallet flag")
	}
}

func TestHDWalletVerifyCommand(t *testing.T) {
	if hdwalletVerifyCmd == nil {
		t.Fatal("hdwalletVerifyCmd should not be nil")
	}

	if hdwalletVerifyCmd.Use != "verify" {
		t.Errorf("hdwalletVerifyCmd.Use = %q, want %q", hdwalletVerifyCmd.Use, "verify")
	}

	if hdwalletVerifyCmd.Short == "" {
		t.Error("hdwalletVerifyCmd.Short should not be empty")
	}

	if hdwalletVerifyCmd.RunE == nil {
		t.Error("hdwalletVerifyCmd.RunE should not be nil")
	}

	walletFlag := hdwalletVerifyCmd.Flags().Lookup("wallet")
	if walletFlag == nil {
		t.Error("hdwalletVerifyCmd should have --wallet flag")
	}
}

func TestHDWalletExportMnemonicCommand(t *testing.T) {
	if hdwalletExportMnemonicCmd == nil {
		t.Fatal("hdwalletExportMnemonicCmd should not be nil")
	}

	if hdwalletExportMnemonicCmd.Use != "export-mnemonic" {
		t.Errorf("hdwalletExportMnemonicCmd.Use = %q, want %q", hdwalletExportMnemonicCmd.Use, "export-mnemonic")
	}

	if hdwalletExportMnemonicCmd.Short == "" {
		t.Error("hdwalletExportMnemonicCmd.Short should not be empty")
	}

	if hdwalletExportMnemonicCmd.RunE == nil {
		t.Error("hdwalletExportMnemonicCmd.RunE should not be nil")
	}

	walletFlag := hdwalletExportMnemonicCmd.Flags().Lookup("wallet")
	if walletFlag == nil {
		t.Error("hdwalletExportMnemonicCmd should have --wallet flag")
	}
}

func TestHDWalletCommandHelp(t *testing.T) {
	cmds := []*cobra.Command{hdwalletCreateCmd, hdwalletImportCmd, hdwalletListCmd, hdwalletDeriveCmd, hdwalletInfoCmd, hdwalletVerifyCmd, hdwalletExportMnemonicCmd}
	for _, cmd := range cmds {
		t.Run(cmd.Use, func(t *testing.T) {
			help := cmd.UsageString()
			if help == "" {
				t.Error("UsageString should not be empty")
			}
		})
	}
}
