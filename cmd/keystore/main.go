package main

import (
	"fmt"
	"os"

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

		password, err := keystore.ReadPasswordWithConfirm("Enter password for new keystore")
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
		privateKey, err := keystore.ReadSecret()
		if err != nil {
			return err
		}
		defer keystore.SecureZeroize(privateKey)

		if len(privateKey) == 0 {
			return fmt.Errorf("private key cannot be empty")
		}

		password, err := keystore.ReadPasswordWithConfirm("Enter password for keystore")
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
		currentPassword, err := keystore.ReadSecret()
		if err != nil {
			return err
		}
		defer keystore.SecureZeroize(currentPassword)

		newPassword, err := keystore.ReadPasswordWithConfirm("Enter new password")
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
		password, err := keystore.ReadSecret()
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

	// Add commands to root
	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(importCmd)
	rootCmd.AddCommand(changePasswordCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(showCmd)
	rootCmd.AddCommand(verifyCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
