package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/ivanzzeth/ethsig/keystore"
	"github.com/spf13/cobra"
)

const version = "1.0.0"

var rootCmd = &cobra.Command{
	Use:   "keystore",
	Short: "Keystore management tool for Ethereum accounts",
	Long: `A command-line tool for managing Ethereum keystores.

Supports creating new keystores, importing private keys, changing passwords,
and listing keystores. All password input is done interactively for security.`,
	Version: version,
}

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new keystore with a randomly generated key",
	Long: `Create a new Ethereum keystore with a randomly generated private key.
The password will be requested interactively (typed twice for confirmation).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := cmd.Flags().GetString("dir")
		if err != nil {
			return fmt.Errorf("failed to get dir flag: %w", err)
		}

		if !keystore.IsTerminal() {
			return fmt.Errorf("this command requires interactive terminal input")
		}

		password, err := keystore.ReadPasswordWithConfirm(cmd.Context(), "Enter password for new keystore")
		if err != nil {
			return err
		}
		defer keystore.SecureZeroize(password)

		address, path, err := keystore.CreateKeystore(dir, password)
		if err != nil {
			return fmt.Errorf("failed to create keystore: %w", err)
		}

		fmt.Println("Keystore created successfully!")
		fmt.Printf("  Address: %s\n", address)
		fmt.Printf("  Path:    %s\n", path)
		return nil
	},
}

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import a private key into a new keystore",
	Long: `Import an existing private key into a new encrypted keystore.
Both the private key and password will be requested interactively.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := cmd.Flags().GetString("dir")
		if err != nil {
			return fmt.Errorf("failed to get dir flag: %w", err)
		}

		if !keystore.IsTerminal() {
			return fmt.Errorf("this command requires interactive terminal input")
		}

		fmt.Print("Enter private key (hex, will not echo): ")
		privateKey, err := keystore.ReadSecret(cmd.Context())
		if err != nil {
			return err
		}
		defer keystore.SecureZeroize(privateKey)

		if len(privateKey) == 0 {
			return fmt.Errorf("private key cannot be empty")
		}

		password, err := keystore.ReadPasswordWithConfirm(cmd.Context(), "Enter password for keystore")
		if err != nil {
			return err
		}
		defer keystore.SecureZeroize(password)

		address, path, err := keystore.ImportPrivateKey(dir, privateKey, password)
		if err != nil {
			return fmt.Errorf("failed to import key: %w", err)
		}

		fmt.Println("Private key imported successfully!")
		fmt.Printf("  Address: %s\n", address)
		fmt.Printf("  Path:    %s\n", path)
		return nil
	},
}

var changePasswordCmd = &cobra.Command{
	Use:   "change-password",
	Short: "Change the password of an existing keystore",
	Long: `Change the password of an existing keystore file.
Both current and new passwords will be requested interactively.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		keystorePath, err := cmd.Flags().GetString("keystore")
		if err != nil {
			return fmt.Errorf("failed to get keystore flag: %w", err)
		}

		if !keystore.IsTerminal() {
			return fmt.Errorf("this command requires interactive terminal input")
		}

		// Show the address being modified
		address, err := keystore.GetKeystoreAddress(keystorePath)
		if err != nil {
			return fmt.Errorf("failed to read keystore: %w", err)
		}
		fmt.Printf("Changing password for keystore: %s\n", address)

		fmt.Print("Enter current password: ")
		currentPassword, err := keystore.ReadSecret(cmd.Context())
		if err != nil {
			return err
		}
		defer keystore.SecureZeroize(currentPassword)

		newPassword, err := keystore.ReadPasswordWithConfirm(cmd.Context(), "Enter new password")
		if err != nil {
			return err
		}
		defer keystore.SecureZeroize(newPassword)

		if err := keystore.ChangePassword(keystorePath, currentPassword, newPassword); err != nil {
			return fmt.Errorf("failed to change password: %w", err)
		}

		fmt.Println("Password changed successfully!")
		return nil
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all keystores in a directory",
	Long:  `List all Ethereum keystore files in the specified directory.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := cmd.Flags().GetString("dir")
		if err != nil {
			return fmt.Errorf("failed to get dir flag: %w", err)
		}

		keystores, err := keystore.ListKeystores(dir)
		if err != nil {
			return fmt.Errorf("failed to list keystores: %w", err)
		}

		if len(keystores) == 0 {
			fmt.Println("No keystores found in", dir)
			return nil
		}

		fmt.Printf("Found %d keystore(s) in %s:\n\n", len(keystores), dir)
		for i, ks := range keystores {
			fmt.Printf("%d. %s\n", i+1, ks.Address)
			fmt.Printf("   Path: %s\n\n", ks.Path)
		}
		return nil
	},
}

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the address of a keystore",
	Long:  `Display the Ethereum address contained in a keystore file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		keystorePath, err := cmd.Flags().GetString("keystore")
		if err != nil {
			return fmt.Errorf("failed to get keystore flag: %w", err)
		}

		address, err := keystore.GetKeystoreAddress(keystorePath)
		if err != nil {
			return fmt.Errorf("failed to read keystore: %w", err)
		}

		fmt.Printf("Address: %s\n", address)
		fmt.Printf("Path:    %s\n", keystorePath)
		return nil
	},
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the password of a keystore",
	Long: `Verify that a password can decrypt a keystore file.
This is useful for testing if you remember the correct password.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		keystorePath, err := cmd.Flags().GetString("keystore")
		if err != nil {
			return fmt.Errorf("failed to get keystore flag: %w", err)
		}

		if !keystore.IsTerminal() {
			return fmt.Errorf("this command requires interactive terminal input")
		}

		address, err := keystore.GetKeystoreAddress(keystorePath)
		if err != nil {
			return fmt.Errorf("failed to read keystore: %w", err)
		}
		fmt.Printf("Verifying password for: %s\n", address)

		fmt.Print("Enter password: ")
		password, err := keystore.ReadSecret(cmd.Context())
		if err != nil {
			return err
		}
		defer keystore.SecureZeroize(password)

		if err := keystore.VerifyPassword(keystorePath, password); err != nil {
			return fmt.Errorf("password verification failed: %w", err)
		}

		fmt.Println("Password verified successfully!")
		return nil
	},
}

// --- HD wallet commands ---

var hdwalletCmd = &cobra.Command{
	Use:   "hdwallet",
	Short: "HD wallet management",
	Long: `Manage BIP-39 mnemonic-based HD wallets for key derivation.

An HD wallet stores an encrypted BIP-39 mnemonic from which any number of
Ethereum addresses and keys can be derived on-the-fly.`,
}

var hdwalletCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new HD wallet with a randomly generated mnemonic",
	Long: `Create a new HD wallet with a randomly generated BIP-39 mnemonic.
The password will be requested interactively (typed twice for confirmation).
The mnemonic is encrypted and stored in an hdwallet.json file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := cmd.Flags().GetString("dir")
		if err != nil {
			return fmt.Errorf("failed to get dir flag: %w", err)
		}

		entropy, err := cmd.Flags().GetInt("entropy")
		if err != nil {
			return fmt.Errorf("failed to get entropy flag: %w", err)
		}

		if !keystore.IsTerminal() {
			return fmt.Errorf("this command requires interactive terminal input")
		}

		password, err := keystore.ReadPasswordWithConfirm(cmd.Context(), "Enter password for new HD wallet")
		if err != nil {
			return err
		}
		defer keystore.SecureZeroize(password)

		address, walletPath, err := keystore.CreateHDWallet(dir, password, entropy)
		if err != nil {
			return fmt.Errorf("failed to create HD wallet: %w", err)
		}

		fmt.Println("HD wallet created successfully!")
		fmt.Printf("  Address: %s\n", address)
		fmt.Printf("  Path:    %s\n", walletPath)
		return nil
	},
}

var hdwalletImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import an existing mnemonic into a new HD wallet",
	Long: `Import an existing BIP-39 mnemonic into a new encrypted HD wallet.
Both the mnemonic and password will be requested interactively.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := cmd.Flags().GetString("dir")
		if err != nil {
			return fmt.Errorf("failed to get dir flag: %w", err)
		}

		if !keystore.IsTerminal() {
			return fmt.Errorf("this command requires interactive terminal input")
		}

		fmt.Print("Enter mnemonic (will not echo): ")
		mnemonic, err := keystore.ReadSecret(cmd.Context())
		if err != nil {
			return err
		}
		defer keystore.SecureZeroize(mnemonic)

		if len(mnemonic) == 0 {
			return fmt.Errorf("mnemonic cannot be empty")
		}

		password, err := keystore.ReadPasswordWithConfirm(cmd.Context(), "Enter password for HD wallet")
		if err != nil {
			return err
		}
		defer keystore.SecureZeroize(password)

		address, walletPath, err := keystore.ImportHDWallet(dir, mnemonic, password)
		if err != nil {
			return fmt.Errorf("failed to import HD wallet: %w", err)
		}

		fmt.Println("HD wallet imported successfully!")
		fmt.Printf("  Address: %s\n", address)
		fmt.Printf("  Path:    %s\n", walletPath)
		return nil
	},
}

var hdwalletListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all HD wallets in a directory",
	Long:  `List all HD wallet files in the specified directory.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := cmd.Flags().GetString("dir")
		if err != nil {
			return fmt.Errorf("failed to get dir flag: %w", err)
		}

		wallets, err := keystore.ListHDWallets(dir)
		if err != nil {
			return fmt.Errorf("failed to list HD wallets: %w", err)
		}

		if len(wallets) == 0 {
			fmt.Println("No HD wallets found in", dir)
			return nil
		}

		fmt.Printf("Found %d HD wallet(s) in %s:\n\n", len(wallets), dir)
		for i, w := range wallets {
			fmt.Printf("%d. %s\n", i+1, w.PrimaryAddress)
			fmt.Printf("   Base Path: %s\n", w.BasePath)
			fmt.Printf("   File:      %s\n\n", w.Path)
		}
		return nil
	},
}

var hdwalletDeriveCmd = &cobra.Command{
	Use:   "derive",
	Short: "Derive addresses from an HD wallet",
	Long:  `Decrypt an HD wallet and derive Ethereum addresses for a range of indices.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		walletPath, err := cmd.Flags().GetString("wallet")
		if err != nil {
			return fmt.Errorf("failed to get wallet flag: %w", err)
		}

		start, err := cmd.Flags().GetUint32("start")
		if err != nil {
			return fmt.Errorf("failed to get start flag: %w", err)
		}

		end, err := cmd.Flags().GetUint32("end")
		if err != nil {
			return fmt.Errorf("failed to get end flag: %w", err)
		}

		if !keystore.IsTerminal() {
			return fmt.Errorf("this command requires interactive terminal input")
		}

		fmt.Print("Enter HD wallet password: ")
		password, err := keystore.ReadSecret(cmd.Context())
		if err != nil {
			return err
		}
		defer keystore.SecureZeroize(password)

		wallet, err := keystore.OpenHDWallet(walletPath, password)
		if err != nil {
			return fmt.Errorf("failed to open HD wallet: %w", err)
		}
		defer wallet.Close()

		addresses, err := wallet.DeriveAddresses(start, end)
		if err != nil {
			return fmt.Errorf("failed to derive addresses: %w", err)
		}

		fmt.Printf("Derived addresses [%d, %d):\n\n", start, end)
		for i, addr := range addresses {
			fmt.Printf("%d. %s\n", start+uint32(i), addr.Hex())
		}
		return nil
	},
}

var hdwalletInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show HD wallet metadata without decryption",
	Long:  `Display the primary address, derivation base path, and file path of an HD wallet.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		walletPath, err := cmd.Flags().GetString("wallet")
		if err != nil {
			return fmt.Errorf("failed to get wallet flag: %w", err)
		}

		info, err := keystore.GetHDWalletInfo(walletPath)
		if err != nil {
			return fmt.Errorf("failed to read HD wallet info: %w", err)
		}

		fmt.Printf("Primary Address: %s\n", info.PrimaryAddress)
		fmt.Printf("Base Path:       %s\n", info.BasePath)
		fmt.Printf("File:            %s\n", info.Path)
		return nil
	},
}

var hdwalletVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the password of an HD wallet",
	Long:  `Verify that a password can decrypt an HD wallet file without exposing any secret material.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		walletPath, err := cmd.Flags().GetString("wallet")
		if err != nil {
			return fmt.Errorf("failed to get wallet flag: %w", err)
		}

		if !keystore.IsTerminal() {
			return fmt.Errorf("this command requires interactive terminal input")
		}

		info, err := keystore.GetHDWalletInfo(walletPath)
		if err != nil {
			return fmt.Errorf("failed to read HD wallet: %w", err)
		}
		fmt.Printf("Verifying password for: %s\n", info.PrimaryAddress)

		fmt.Print("Enter password: ")
		password, err := keystore.ReadSecret(cmd.Context())
		if err != nil {
			return err
		}
		defer keystore.SecureZeroize(password)

		if err := keystore.VerifyHDWalletPassword(walletPath, password); err != nil {
			return fmt.Errorf("password verification failed: %w", err)
		}

		fmt.Println("Password verified successfully!")
		return nil
	},
}

var hdwalletExportMnemonicCmd = &cobra.Command{
	Use:   "export-mnemonic",
	Short: "Export the mnemonic from an HD wallet",
	Long: `Decrypt and display the BIP-39 mnemonic stored in an HD wallet.
WARNING: The mnemonic gives full access to all derived keys. Handle with care.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		walletPath, err := cmd.Flags().GetString("wallet")
		if err != nil {
			return fmt.Errorf("failed to get wallet flag: %w", err)
		}

		if !keystore.IsTerminal() {
			return fmt.Errorf("this command requires interactive terminal input")
		}

		fmt.Print("Type 'yes' to confirm mnemonic export: ")
		reader := bufio.NewReader(os.Stdin)
		confirmation, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		if strings.TrimSpace(confirmation) != "yes" {
			return fmt.Errorf("export cancelled")
		}

		fmt.Print("Enter HD wallet password: ")
		password, err := keystore.ReadSecret(cmd.Context())
		if err != nil {
			return err
		}
		defer keystore.SecureZeroize(password)

		mnemonic, err := keystore.ExportMnemonic(walletPath, password)
		if err != nil {
			return fmt.Errorf("failed to export mnemonic: %w", err)
		}
		defer keystore.SecureZeroize(mnemonic)

		fmt.Println("\nMnemonic:")
		fmt.Println(string(mnemonic))
		return nil
	},
}

func init() {
	// Create command flags
	createCmd.Flags().StringP("dir", "d", "./keystores", "Directory to store the keystore")
	if err := createCmd.MarkFlagRequired("dir"); err != nil {
		panic(err)
	}

	// Import command flags
	importCmd.Flags().StringP("dir", "d", "./keystores", "Directory to store the keystore")
	if err := importCmd.MarkFlagRequired("dir"); err != nil {
		panic(err)
	}

	// Change password command flags
	changePasswordCmd.Flags().StringP("keystore", "k", "", "Path to keystore file")
	if err := changePasswordCmd.MarkFlagRequired("keystore"); err != nil {
		panic(err)
	}

	// List command flags
	listCmd.Flags().StringP("dir", "d", "./keystores", "Directory containing keystores")
	if err := listCmd.MarkFlagRequired("dir"); err != nil {
		panic(err)
	}

	// Show command flags
	showCmd.Flags().StringP("keystore", "k", "", "Path to keystore file")
	if err := showCmd.MarkFlagRequired("keystore"); err != nil {
		panic(err)
	}

	// Verify command flags
	verifyCmd.Flags().StringP("keystore", "k", "", "Path to keystore file")
	if err := verifyCmd.MarkFlagRequired("keystore"); err != nil {
		panic(err)
	}

	// HD wallet create command flags
	hdwalletCreateCmd.Flags().StringP("dir", "d", "./hdwallets", "Directory to store the HD wallet")
	hdwalletCreateCmd.Flags().Int("entropy", 128, "Entropy bits for mnemonic (128 or 256)")

	// HD wallet import command flags
	hdwalletImportCmd.Flags().StringP("dir", "d", "./hdwallets", "Directory to store the HD wallet")

	// HD wallet list command flags
	hdwalletListCmd.Flags().StringP("dir", "d", "./hdwallets", "Directory containing HD wallets")

	// HD wallet derive command flags
	hdwalletDeriveCmd.Flags().StringP("wallet", "w", "", "Path to HD wallet file")
	if err := hdwalletDeriveCmd.MarkFlagRequired("wallet"); err != nil {
		panic(err)
	}
	hdwalletDeriveCmd.Flags().Uint32("start", 0, "Start index for address derivation")
	hdwalletDeriveCmd.Flags().Uint32("end", 10, "End index for address derivation (exclusive)")

	// HD wallet info command flags
	hdwalletInfoCmd.Flags().StringP("wallet", "w", "", "Path to HD wallet file")
	if err := hdwalletInfoCmd.MarkFlagRequired("wallet"); err != nil {
		panic(err)
	}

	// HD wallet verify command flags
	hdwalletVerifyCmd.Flags().StringP("wallet", "w", "", "Path to HD wallet file")
	if err := hdwalletVerifyCmd.MarkFlagRequired("wallet"); err != nil {
		panic(err)
	}

	// HD wallet export-mnemonic command flags
	hdwalletExportMnemonicCmd.Flags().StringP("wallet", "w", "", "Path to HD wallet file")
	if err := hdwalletExportMnemonicCmd.MarkFlagRequired("wallet"); err != nil {
		panic(err)
	}

	// Register HD wallet subcommands
	hdwalletCmd.AddCommand(hdwalletCreateCmd, hdwalletImportCmd, hdwalletListCmd, hdwalletDeriveCmd, hdwalletInfoCmd, hdwalletVerifyCmd, hdwalletExportMnemonicCmd)

	// Add commands to root
	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(importCmd)
	rootCmd.AddCommand(changePasswordCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(showCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(hdwalletCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
