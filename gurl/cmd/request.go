package cmd

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jlaffaye/ftp"
	"github.com/icholy/digest"
	"github.com/vadimi/go-http-ntlm"
)

func ExecuteRequest(requestURL string, verbose bool, include bool, head bool, silent bool, headers []string, method string, data string, outputFile string, remoteName bool, followRedirects bool, user string, proxy string, connectTimeout int, maxTime int, cookie string, cookieJar string, form []string, insecure bool, dataUrlEncode []string, dataBinary string, resolve []string, limitRate string, compressed bool) {
	if strings.HasPrefix(requestURL, "ftp://") {
		executeFTPRequest(requestURL, user, outputFile, remoteName, connectTimeout, maxTime)
	} else {
				executeHTTPRequest(requestURL, verbose, include, head, silent, headers, method, data, outputFile, remoteName, followRedirects, user, proxy, connectTimeout, maxTime, cookie, cookieJar, form, insecure, dataUrlEncode, dataBinary, resolve, limitRate, compressed)
	}
}

func executeHTTPRequest(requestURL string, verbose bool, include bool, head bool, silent bool, headers []string, method string, data string, outputFile string, remoteName bool, followRedirects bool, user string, proxy string, connectTimeout int, maxTime int, cookie string, cookieJar string, form []string, insecure bool, dataUrlEncode []string, dataBinary string, resolve []string, limitRate string, compressed bool) {
	var reqBody io.Reader
	var contentType string

	if len(form) > 0 {
		// Handle multipart form data
		bodyBuf := &bytes.Buffer{}
		writer := multipart.NewWriter(bodyBuf)

		for _, f := range form {
			parts := strings.SplitN(f, "=", 2)
			if len(parts) != 2 {
				fmt.Fprintf(os.Stderr, "Warning: Invalid form data format '%s'. Expected 'key=value' or 'key=@file'.\n", f)
				continue
			}
			key := parts[0]
			value := parts[1]

			if strings.HasPrefix(value, "@") {
				// Handle file upload
				filePath := value[1:]
				file, err := os.Open(filePath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error opening file for form upload '%s': %v\n", filePath, err)
					continue
				}
				defer file.Close()

				part, err := writer.CreateFormFile(key, filepath.Base(filePath))
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error creating form file part: %v\n", err)
					continue
				}
				_, err = io.Copy(part, file)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error writing file to form part: %v\n", err)
					continue
				}
			} else {
				// Handle regular field
				writer.WriteField(key, value)
			}
		}
		writer.Close()
		reqBody = bodyBuf
		contentType = writer.FormDataContentType()
	} else if data != "" {
		// Handle -d data
		reqBody = bytes.NewBuffer([]byte(data))
		// Default content type for -d if not specified by -H
        contentType = "application/x-www-form-urlencoded"
    } else if len(dataUrlEncode) > 0 {
        if data != "" {
            fmt.Fprintf(os.Stderr, "Warning: You can only use one of --data, --data-urlencode, or --form.\n")
            os.Exit(1)
        }
        formValues := url.Values{}
        for _, d := range dataUrlEncode {
            parts := strings.SplitN(d, "=", 2)
            if len(parts) == 2 {
                formValues.Add(parts[0], parts[1])
            } else {
                formValues.Add(d, "")
            }
        }
        reqBody = bytes.NewBuffer([]byte(formValues.Encode()))
        contentType = "application/x-www-form-urlencoded"
    } else if dataBinary != "" {
        if data != "" || len(dataUrlEncode) > 0 || len(form) > 0 {
            fmt.Fprintf(os.Stderr, "Warning: You can only use one of --data, --data-urlencode, --data-binary, or --form.\n")
            os.Exit(1)
        }
        reqBody = bytes.NewBuffer([]byte(dataBinary))
        // Content-Type is not set by default for --data-binary, curl leaves it to the user
    }

    // Apply rate limit if specified
    if limitRate != "" && reqBody != nil {
        limit, err := parseRate(limitRate)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error parsing limit-rate: %v\n", err)
            os.Exit(1)
        }
        if limit > 0 {
            reqBody = &RateLimitedReader{Reader: reqBody, Limit: limit}
        }
    }

	if silent {
		null, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0755)
		defer null.Close()
		os.Stderr = null
	}

	if head {
		method = "HEAD"
		include = true
	}

	req, err := http.NewRequest(method, requestURL, reqBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating request: %v\n", err)
		os.Exit(1)
	}

	// Set Content-Type header if determined by form or data
	if contentType != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Add custom headers
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		} else {
			fmt.Fprintf(os.Stderr, "Warning: Invalid header format '%s'. Expected 'Key: Value'.\n", h)
		}
	}

	// Handle compressed response
	if compressed {
		req.Header.Set("Accept-Encoding", "gzip, deflate")
	}

	// Handle --resolve option
	resolvedAddresses := make(map[string]string)
	for _, r := range resolve {
		parts := strings.SplitN(r, ":", 3)
		if len(parts) == 3 {
			host := parts[0]
			port := parts[1]
			address := parts[2]
			resolvedAddresses[net.JoinHostPort(host, port)] = address
		} else {
			fmt.Fprintf(os.Stderr, "Warning: Invalid resolve format '%s'. Expected 'host:port:address'.\n", r)
		}
	}

	// Create a custom DialContext that uses resolved addresses
	customDialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if resolvedAddr, ok := resolvedAddresses[addr]; ok {
			fmt.Fprintf(os.Stderr, "Info: Resolving %s to %s\n", addr, resolvedAddr)
			return (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext(ctx, network, resolvedAddr)
		}
		return (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext(ctx, network, addr)
	}

	tr := &http.Transport{
		DialContext: customDialContext,
	}

	// Set connect timeout
	if connectTimeout > 0 {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   time.Duration(connectTimeout) * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}
			return dialer.DialContext(ctx, network, addr)
		}
	}

	// Set proxy
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing proxy URL: %v\n", err)
			os.Exit(1)
		}
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// Handle Digest Authentication
	var authTransport http.RoundTripper = tr
	if user != "" {
		parts := strings.SplitN(user, ":", 2)
		if len(parts) == 2 {
			username := parts[0]
			password := parts[1]
			domain := ""

			domainParts := strings.SplitN(username, "\\", 2)
			if len(domainParts) == 2 {
				domain = domainParts[0]
				username = domainParts[1]
			}

			// Check if NTLM authentication is requested (e.g., by a specific header or implicit)
			// For simplicity, let's assume if domain is present, it's NTLM, otherwise Digest
			if domain != "" {
				fmt.Fprintf(os.Stderr, "Info: Attempting NTLM authentication for user %s\\%s\n", domain, username)
				authTransport = &httpntlm.NtlmTransport{
					Domain: domain,
					User: username,
					Password: password,
				}
			} else {
				fmt.Fprintf(os.Stderr, "Info: Attempting Digest authentication for user %s\n", username)
				authTransport = &digest.Transport{
					Username: username,
					Password: password,
					Transport: tr,
				}
			}
		} else if len(parts) == 1 {
			fmt.Fprintf(os.Stderr, "Warning: Digest/NTLM authentication requires a password. Using empty password.\n")
			authTransport = &digest.Transport{
				Username: parts[0],
				Password: "",
				Transport: tr,
			}
		}
	}

	client := &http.Client{
		Transport: authTransport,
	}

	// Set total timeout
	if maxTime > 0 {
		client.Timeout = time.Duration(maxTime) * time.Second
	}

	if !followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Handle cookies
	var jar *cookiejar.Jar
	parsedURL, _ := url.Parse(requestURL)

	// Initialize cookie jar if --cookie-jar is used or if --cookie is used and no jar is yet created
	if cookieJar != "" || cookie != "" {
		var newErr error
		jar, newErr = cookiejar.New(nil)
		if newErr != nil {
			fmt.Fprintf(os.Stderr, "Error creating cookie jar: %v\n", newErr)
			os.Exit(1)
		}
		client.Jar = jar

		// Load cookies from file if --cookie-jar is specified and file exists
		if cookieJar != "" {
			if _, err := os.Stat(cookieJar); err == nil {
				file, err := os.Open(cookieJar)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error opening cookie jar file: %v\n", err)
					os.Exit(1)
				}
				defer file.Close()

				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := scanner.Text()
					if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
						continue // Skip comments and empty lines
					}
					parts := strings.Split(line, "\t")
					if len(parts) == 7 {
						domain := parts[0]
						path := parts[2]
						secure := parts[3] == "TRUE"
						expirationUnix, _ := strconv.ParseInt(parts[4], 10, 64)
						name := parts[5]
						value := parts[6]

						cookie := &http.Cookie{
							Name:    name,
							Value:   value,
							Path:    path,
							Domain:  domain,
							Secure:  secure,
							Expires: time.Unix(expirationUnix, 0),
						}
						jar.SetCookies(parsedURL, []*http.Cookie{cookie})
					} else {
						fmt.Fprintf(os.Stderr, "Warning: Malformed cookie line in %s: %s\n", cookieJar, line)
					}
				}
				if err := scanner.Err(); err != nil {
					fmt.Fprintf(os.Stderr, "Error reading cookie jar file: %v\n", err)
					os.Exit(1)
				}
			}
		}

		// Add cookies from -b flag
		if cookie != "" {
			cookieParts := strings.Split(cookie, ";")
			for _, cp := range cookieParts {
				pair := strings.SplitN(strings.TrimSpace(cp), "=", 2)
				if len(pair) == 2 {
					jar.SetCookies(parsedURL, []*http.Cookie{{Name: pair[0], Value: pair[1]}})
				} else if len(pair) == 1 {
					jar.SetCookies(parsedURL, []*http.Cookie{{Name: pair[0], Value: ""}})
				}
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error making request: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// Decompress response body if compressed flag is set and content encoding is present
	var respBodyReader io.Reader = resp.Body
	if compressed {
		contentEncoding := resp.Header.Get("Content-Encoding")
		if contentEncoding == "gzip" {
			gzipReader, gzipErr := gzip.NewReader(resp.Body)
			if gzipErr != nil {
				fmt.Fprintf(os.Stderr, "Error creating gzip reader: %v\n", gzipErr)
				os.Exit(1)
			}
			defer gzipReader.Close()
			respBodyReader = gzipReader
		} else if contentEncoding == "deflate" {
			deflateReader := flate.NewReader(resp.Body)
			defer deflateReader.Close()
			respBodyReader = deflateReader
		}
	}

	// Save cookies to file if cookieJar is specified
	if cookieJar != "" && jar != nil {
		file, err := os.Create(cookieJar)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating cookie jar file for writing: %v\n", err)
			// Do not exit, just warn, as response body might still be useful
		} else {
			defer file.Close()
			cookies := jar.Cookies(parsedURL)
			for _, c := range cookies {
				// Netscape cookie file format
				// domain<tab>flag<tab>path<tab>secure<tab>expiration<tab>name<tab>value
				// flag: TRUE if host-only, FALSE if domain-wide
				// secure: TRUE if secure, FALSE otherwise
				// expiration: Unix timestamp

				flag := "FALSE"
				// Determine if it's a host-only cookie (no leading dot in domain)
				if !strings.HasPrefix(c.Domain, ".") {
					flag = "TRUE"
				}

				secure := "FALSE"
				if c.Secure {
					secure = "TRUE"
				}

				expiration := "0"
				if !c.Expires.IsZero() {
					expiration = fmt.Sprintf("%d", c.Expires.Unix())
				}
				fmt.Fprintf(file, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", c.Domain, flag, c.Path, secure, expiration, c.Name, c.Value)
			}
		}
	}

	// Print request details if verbose
	if verbose {
		fmt.Fprintf(os.Stderr, ">%s %s HTTP/1.1\n", req.Method, req.URL.RequestURI())
		for name, values := range req.Header {
			for _, value := range values {
				fmt.Fprintf(os.Stderr, ">%s: %s\n", name, value)
			}
		}
		if req.Body != nil && data != "" {
			fmt.Fprintf(os.Stderr, "> Request Body: %s\n", data)
		}
		fmt.Fprintln(os.Stderr, "> \n")
	}

	// Print response details if verbose
	if verbose {
		fmt.Fprintf(os.Stderr, "< HTTP/1.1 %s\n", resp.Status)
		for name, values := range resp.Header {
			for _, value := range values {
				fmt.Fprintf(os.Stderr, "<%s: %s\n", name, value)
			}
		}
		fmt.Fprintln(os.Stderr, "< \n")
	}

	if resp.StatusCode >= 400 && resp.StatusCode < 300 {
		fmt.Fprintf(os.Stderr, "Error: Received status code %d\n", resp.StatusCode)
		// Attempt to read body even on error for more info
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			fmt.Fprintf(os.Stderr, "Response Body: %s\n", string(body))
		}
		os.Exit(1)
	}

	var writer io.Writer
	if remoteName {
		parsedURL, err := url.Parse(requestURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing URL for remote name: %v\n", err)
			os.Exit(1)
		}
		outputFile = filepath.Base(parsedURL.Path)
	}

	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		writer = file
	} else {
		writer = os.Stdout
	}

	if include {
		fmt.Fprintf(writer, "HTTP/1.1 %s\n", resp.Status)
		for name, values := range resp.Header {
			for _, value := range values {
				fmt.Fprintf(writer, "%s: %s\n", name, value)
			}
		}
        fmt.Fprintln(writer, "")
    }

    if !head {
        _, err = io.Copy(writer, respBodyReader)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error writing response body: %v\n", err)
            os.Exit(1)
        }
    }
}

// RateLimitedReader wraps an io.Reader and limits its read rate.
type RateLimitedReader struct {
	Reader io.Reader
	Limit  int64 // bytes per second
	lastReadTime time.Time
	lastReadBytes int64
}

func (r *RateLimitedReader) Read(p []byte) (n int, err error) {
	now := time.Now()
	if r.lastReadTime.IsZero() {
		r.lastReadTime = now
	}

	elapsed := now.Sub(r.lastReadTime)
	if elapsed > 0 {
		expectedBytes := int64(float64(r.Limit) * elapsed.Seconds())
		if r.lastReadBytes > expectedBytes {
			sleepTime := time.Duration(float64(r.lastReadBytes - expectedBytes) / float64(r.Limit) * float64(time.Second))
			time.Sleep(sleepTime)
		}
	}

	n, err = r.Reader.Read(p)
	r.lastReadBytes += int64(n)
	r.lastReadTime = time.Now()
	return
}

func parseRate(rateStr string) (int64, error) {
	rateStr = strings.ToLower(strings.TrimSpace(rateStr))
	if rateStr == "" {
		return 0, nil
	}

	multiplier := int64(1)
	if strings.HasSuffix(rateStr, "k") {
		multiplier = 1024
		rateStr = strings.TrimSuffix(rateStr, "k")
	} else if strings.HasSuffix(rateStr, "m") {
		multiplier = 1024 * 1024
		rateStr = strings.TrimSuffix(rateStr, "m")
	} else if strings.HasSuffix(rateStr, "g") {
		multiplier = 1024 * 1024 * 1024
		rateStr = strings.TrimSuffix(rateStr, "g")
	}

	rate, err := strconv.ParseInt(rateStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid rate format: %w", err)
	}

	return rate * multiplier, nil
}

func executeFTPRequest(requestURL string, user string, outputFile string, remoteName bool, connectTimeout int, maxTime int) {
	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing FTP URL: %v\n", err)
		os.Exit(1)
	}

	host := parsedURL.Host
	path := parsedURL.Path

	username := "anonymous"
	password := "anonymous"

	if parsedURL.User != nil {
		username = parsedURL.User.Username()
		if p, ok := parsedURL.User.Password(); ok {
			password = p
		}
	} else if user != "" {
		parts := strings.SplitN(user, ":", 2)
		if len(parts) == 2 {
			username = parts[0]
			password = parts[1]
		} else {
			username = parts[0]
		}
	}

	var c *ftp.ServerConn
	connEstablished := make(chan error, 1)
	go func() {
		c, err = ftp.Dial(host)
		connEstablished <- err
	}()

	if maxTime > 0 {
		select {
		case err = <-connEstablished:
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error connecting to FTP server: %v\n", err)
				os.Exit(1)
			}
		case <-time.After(time.Duration(maxTime) * time.Second):
			fmt.Fprintf(os.Stderr, "FTP connection timed out after %d seconds\n", maxTime)
			os.Exit(1)
		}
	} else {
		if err = <-connEstablished; err != nil {
			fmt.Fprintf(os.Stderr, "Error connecting to FTP server: %v\n", err)
			os.Exit(1)
		}
	}

	defer c.Quit()

	err = c.Login(username, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error logging into FTP server: %v\n", err)
		os.Exit(1)
	}

	r, err := c.Retr(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving file from FTP server: %v\n", err)
		os.Exit(1)
	}
	defer r.Close()

	var writer io.Writer
	if remoteName {
		outputFile = filepath.Base(path)
	}

	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		writer = file
	} else {
		writer = os.Stdout
	}

	_, err = io.Copy(writer, r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing FTP response to output: %v\n", err)
		os.Exit(1)
	}
}