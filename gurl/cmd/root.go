package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gurl",
	Short: "gurl is a curl clone in Go",
	Long:  `A feature-rich curl clone written in Go, aiming for full compatibility with the original curl.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		verbose, _ := cmd.Flags().GetBool("verbose")
		include, _ := cmd.Flags().GetBool("include")
		head, _ := cmd.Flags().GetBool("head")
		silent, _ := cmd.Flags().GetBool("silent")
		headers, _ := cmd.Flags().GetStringArray("header")
		method, _ := cmd.Flags().GetString("request")
		data, _ := cmd.Flags().GetString("data")
		outputFile, _ := cmd.Flags().GetString("output")
		remoteName, _ := cmd.Flags().GetBool("remote-name")
		followRedirects, _ := cmd.Flags().GetBool("location")
		user, _ := cmd.Flags().GetString("user")
		proxy, _ := cmd.Flags().GetString("proxy")
		connectTimeout, _ := cmd.Flags().GetInt("connect-timeout")
		maxTime, _ := cmd.Flags().GetInt("max-time")
		cookie, _ := cmd.Flags().GetString("cookie")
		cookieJar, _ := cmd.Flags().GetString("cookie-jar")
		form, _ := cmd.Flags().GetStringArray("form")
		insecure, _ := cmd.Flags().GetBool("insecure")
		dataUrlEncode, _ := cmd.Flags().GetStringArray("data-urlencode")
		dataBinary, _ := cmd.Flags().GetString("data-binary")
		resolve, _ := cmd.Flags().GetStringArray("resolve")
		limitRate, _ := cmd.Flags().GetString("limit-rate")
		compressed, _ := cmd.Flags().GetBool("compressed")
		userAgent, _ := cmd.Flags().GetString("user-agent")
		retry, _ := cmd.Flags().GetInt("retry")
		retryDelay, _ := cmd.Flags().GetInt("retry-delay")
		ExecuteRequest(args[0], verbose, include, head, silent, headers, method, data, outputFile, remoteName, followRedirects, user, proxy, connectTimeout, maxTime, cookie, cookieJar, form, insecure, dataUrlEncode, dataBinary, resolve, limitRate, compressed, userAgent, retry, retryDelay)
	},
}

func init() {
	rootCmd.Flags().StringP("request", "X", "GET", "Specify request command to use")
	rootCmd.Flags().StringArrayP("header", "H", []string{}, "Pass custom header(s) to server")
	rootCmd.Flags().StringP("data", "d", "", "HTTP POST data")
	rootCmd.Flags().StringP("output", "o", "", "Write to file instead of stdout")
	rootCmd.Flags().BoolP("remote-name", "O", false, "Write output to a file named as the remote file")
	rootCmd.Flags().BoolP("verbose", "v", false, "Make the operation more talkative")
	rootCmd.Flags().BoolP("include", "i", false, "Include protocol response headers in the output")
	rootCmd.Flags().BoolP("head", "I", false, "Show document info only")
	rootCmd.Flags().BoolP("silent", "s", false, "Silent mode")
	rootCmd.Flags().BoolP("location", "L", false, "Follow redirects")
	rootCmd.Flags().StringP("user", "u", "", "Server user and password")
	rootCmd.Flags().StringP("proxy", "x", "", "Proxy host and port")
	rootCmd.Flags().Int("connect-timeout", 0, "Maximum time in seconds that you allow the connection to the server to take")
	rootCmd.Flags().Int("max-time", 0, "Maximum time in seconds that you allow the whole operation to take")
	rootCmd.Flags().StringP("cookie", "b", "", "Send cookies from string/file")
	rootCmd.Flags().StringP("cookie-jar", "c", "", "Write cookies to <filename> after operation")
	rootCmd.Flags().StringArrayP("form", "F", []string{}, "Specify multipart MIME data")
	rootCmd.Flags().BoolP("insecure", "k", false, "Allow insecure server connections when using SSL")
	rootCmd.Flags().StringArray("data-urlencode", []string{}, "HTTP POST data url encoded")
	rootCmd.Flags().String("data-binary", "", "HTTP POST data (binary)")
	rootCmd.Flags().StringArray("resolve", []string{}, "Provide a custom address for a specific host and port pair")
	rootCmd.Flags().String("limit-rate", "", "Limit data transfer speed")
	rootCmd.Flags().Bool("compressed", false, "Request compressed response (e.g., gzip, deflate)")
	rootCmd.Flags().StringP("user-agent", "A", "", "Specify User-Agent string to send to the HTTP server")
	rootCmd.Flags().Int("retry", 0, "Maximum number of retries for transient errors")
	rootCmd.Flags().Int("retry-delay", 1, "Delay between retries in seconds")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your CLI '%s'", err)
		os.Exit(1)
	}
}
