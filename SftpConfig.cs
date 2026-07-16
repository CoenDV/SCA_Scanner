namespace SCAScanner;

/// <summary>
/// Immutable configuration for SFTP server connection and upload settings.
/// </summary>
public class SftpConfig
{
    /// <summary>SFTP server hostname or IP address (required if SFTP is enabled).</summary>
    public string? Host { get; init; }

    /// <summary>SFTP server port (default: 22).</summary>
    public int Port { get; init; } = 22;

    /// <summary>Username for SFTP authentication.</summary>
    public string? User { get; init; }

    /// <summary>Password for SFTP authentication (null if using key-based auth).</summary>
    public string? Password { get; init; }

    /// <summary>Path to SSH private key file for key-based authentication.</summary>
    public string? KeyPath { get; init; }

    /// <summary>Remote directory path for uploads (default: "/").</summary>
    public string RemotePath { get; init; } = "/";

    /// <summary>
    /// Returns true if SFTP upload is enabled (Host is provided).
    /// </summary>
    public bool Enabled => !string.IsNullOrWhiteSpace(Host);

    /// <summary>
    /// Validates the configuration and throws if required values are missing.
    /// </summary>
    public void Validate()
    {
        if (!Enabled)
            throw new InvalidOperationException("SFTP host is required when SFTP upload is enabled");

        if (string.IsNullOrWhiteSpace(User))
            throw new InvalidOperationException("SFTP username is required");

        if (string.IsNullOrWhiteSpace(Password) && string.IsNullOrWhiteSpace(KeyPath))
            throw new ArgumentException("SFTP authentication requires either --sftp-pass or --sftp-key");
    }
}
