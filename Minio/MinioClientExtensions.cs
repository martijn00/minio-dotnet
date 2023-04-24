using Minio.Credentials;
using Minio.DataModel;
using Minio.Exceptions;
using Minio.Helper;
using System.Diagnostics;
using System.Net;

namespace Minio;

public static class MinioClientExtensions
{
    public static IMinioClient WithEndpoint(this IMinioClient minioClient, string endpoint)
    {
        if (minioClient is null) throw new ArgumentNullException(nameof(minioClient));

        minioClient.BaseUrl = endpoint;
        minioClient.SetBaseURL(GetBaseUrl(endpoint));
        return minioClient;
    }

    public static IMinioClient WithEndpoint(this IMinioClient minioClient, string endpoint, int port)
    {
        if (minioClient is null) throw new ArgumentNullException(nameof(minioClient));

        if (port < 1 || port > 65535)
            throw new ArgumentException(string.Format("Port {0} is not a number between 1 and 65535", port),
                nameof(port));
        return minioClient.WithEndpoint(endpoint + ":" + port);
    }

    public static IMinioClient WithEndpoint(this IMinioClient minioClient, Uri url)
    {
        if (minioClient is null) throw new ArgumentNullException(nameof(minioClient));

        if (url is null) throw new ArgumentNullException(nameof(url));

        return minioClient.WithEndpoint(url.AbsoluteUri);
    }

    public static IMinioClient WithRegion(this IMinioClient minioClient, string region)
    {
        if (minioClient is null) throw new ArgumentNullException(nameof(minioClient));

        if (string.IsNullOrEmpty(region))
            throw new ArgumentException(string.Format("{0} the region value can't be null or empty.", region),
                nameof(region));

        minioClient.Region = region;
        return minioClient;
    }

    public static IMinioClient WithRegion(this IMinioClient minioClient)
    {
        if (minioClient is null) throw new ArgumentNullException(nameof(minioClient));
        // Set region to its default value if empty or null
        minioClient.Region = "us-east-1";
        return minioClient;
    }

    public static IMinioClient WithCredentials(this IMinioClient minioClient, string accessKey, string secretKey)
    {
        if (minioClient is null) throw new ArgumentNullException(nameof(minioClient));

        minioClient.AccessKey = accessKey;
        minioClient.SecretKey = secretKey;
        return minioClient;
    }

    public static IMinioClient WithSessionToken(this IMinioClient minioClient, string st)
    {
        if (minioClient is null) throw new ArgumentNullException(nameof(minioClient));

        minioClient.SessionToken = st;
        return minioClient;
    }


    /// <summary>
    ///     Connects to Cloud Storage with HTTPS if this method is invoked on client object
    /// </summary>
    /// <returns></returns>
    public static IMinioClient WithSSL(this IMinioClient minioClient, bool secure = true)
    {
        if (minioClient is null) throw new ArgumentNullException(nameof(minioClient));

        if (secure)
        {
            minioClient.Secure = true;
            if (string.IsNullOrEmpty(minioClient.BaseUrl))
                return minioClient;
            var secureUrl = RequestUtil.MakeTargetURL(minioClient.BaseUrl, minioClient.Secure);
        }

        return minioClient;
    }

    /// <summary>
    ///     Uses webproxy for all requests if this method is invoked on client object.
    /// </summary>
    /// <param name="proxy">Information on the proxy server in the setup.</param>
    /// <returns></returns>
    public static IMinioClient WithProxy(this IMinioClient minioClient, IWebProxy proxy)
    {
        if (minioClient is null) throw new ArgumentNullException(nameof(minioClient));

        minioClient.Proxy = proxy;
        return minioClient;
    }

    /// <summary>
    ///     Uses the set timeout for all requests if this method is invoked on client object
    /// </summary>
    /// <param name="timeout">Timeout in milliseconds.</param>
    /// <returns></returns>
    public static IMinioClient WithTimeout(this IMinioClient minioClient, int timeout)
    {
        if (minioClient is null) throw new ArgumentNullException(nameof(minioClient));

        minioClient.RequestTimeout = timeout;
        return minioClient;
    }

    /// <summary>
    ///     Allows to add retry policy handler
    /// </summary>
    /// <param name="retryPolicyHandler">Delegate that will wrap execution of http client requests.</param>
    /// <returns></returns>
    public static IMinioClient WithRetryPolicy(this IMinioClient minioClient, RetryPolicyHandlingDelegate retryPolicyHandler)
    {
        if (minioClient is null) throw new ArgumentNullException(nameof(minioClient));

        minioClient.RetryPolicyHandler = retryPolicyHandler;
        return minioClient;
    }

    /// <summary>
    ///     Allows end user to define the Http server and pass it as a parameter
    /// </summary>
    /// <param name="httpClient"> Instance of HttpClient</param>
    /// <param name="disposeHttpClient"> Dispose the HttpClient when leaving</param>
    /// <returns></returns>
    public static IMinioClient WithHttpClient(this IMinioClient minioClient, HttpClient httpClient, bool disposeHttpClient = false)
    {
        if (minioClient is null) throw new ArgumentNullException(nameof(minioClient));

        if (httpClient != null) minioClient.HttpClient = httpClient;
        minioClient.DisposeHttpClient = disposeHttpClient;
        return minioClient;
    }

    /// <summary>
    ///     With provider for credentials and session token if being used
    /// </summary>
    /// <returns></returns>
    public static IMinioClient WithCredentialsProvider(this IMinioClient minioClient, ClientProvider provider)
    {
        if (minioClient is null) throw new ArgumentNullException(nameof(minioClient));

        minioClient.Provider = provider;
        AccessCredentials credentials;
        if (minioClient.Provider is IAMAWSProvider)
            // Empty object, we need the Minio client completely
            credentials = new AccessCredentials();
        else
            credentials = minioClient.Provider.GetCredentials();

        if (credentials == null)
            // Unable to fetch credentials.
            return minioClient;

        minioClient.AccessKey = credentials.AccessKey;
        minioClient.SecretKey = credentials.SecretKey;
        var isSessionTokenAvailable = !string.IsNullOrEmpty(credentials.SessionToken);
        if ((minioClient.Provider is AWSEnvironmentProvider ||
             minioClient.Provider is IAMAWSProvider ||
             minioClient.Provider is CertificateIdentityProvider ||
             (minioClient.Provider is ChainedProvider chainedProvider && chainedProvider.CurrentProvider is AWSEnvironmentProvider))
            && isSessionTokenAvailable)
            minioClient.SessionToken = credentials.SessionToken;

        return minioClient;
    }

    /// <summary>
    ///     Sets app version and name. Used for constructing User-Agent header in all HTTP requests
    /// </summary>
    /// <param name="appName"></param>
    /// <param name="appVersion"></param>
    public static void SetAppInfo(this IMinioClient minioClient, string appName, string appVersion)
    {
        if (minioClient is null) throw new ArgumentNullException(nameof(minioClient));

        if (string.IsNullOrEmpty(appName))
            throw new ArgumentException("Appname cannot be null or empty", nameof(appName));

        if (string.IsNullOrEmpty(appVersion))
            throw new ArgumentException("Appversion cannot be null or empty", nameof(appVersion));

        minioClient.CustomUserAgent = $"{appName}/{appVersion}";
    }

    /// <summary>
    ///     Sets HTTP tracing On.Writes output to Console
    /// </summary>
    public static void SetTraceOn(this IMinioClient minioClient, IRequestLogger logger = null)
    {
        if (minioClient is null) throw new ArgumentNullException(nameof(minioClient));

        minioClient.logger = logger ?? new DefaultRequestLogger();
        minioClient.Trace = true;
    }

    /// <summary>
    ///     Sets HTTP tracing Off.
    /// </summary>
    public static void SetTraceOff(this IMinioClient minioClient)
    {
        if (minioClient is null) throw new ArgumentNullException(nameof(minioClient));

        minioClient.Trace = false;
    }

    public static IMinioClient Build(this IMinioClient minioClient)
    {
        if (minioClient is null) throw new ArgumentNullException(nameof(minioClient));
        // Instantiate a region cache
        minioClient.regionCache = BucketRegionCache.Instance;
        if (string.IsNullOrEmpty(minioClient.BaseUrl)) throw new MinioException("Endpoint not initialized.");
        if (minioClient.Provider != null && minioClient.Provider.GetType() != typeof(ChainedProvider) &&
            minioClient.SessionToken == null)
            throw new MinioException("User Access Credentials Provider not initialized correctly.");
        if (minioClient.Provider == null &&
            (string.IsNullOrEmpty(minioClient.AccessKey) || string.IsNullOrEmpty(minioClient.SecretKey)))
            throw new MinioException("User Access Credentials not initialized.");

        var host = minioClient.BaseUrl;

        var scheme = minioClient.Secure ? Utils.UrlEncode("https") : Utils.UrlEncode("http");

        if (!minioClient.BaseUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            minioClient.Endpoint = string.Format("{0}://{1}", scheme, host);
        else
            minioClient.Endpoint = host;

        minioClient.HttpClient ??= minioClient.Proxy is null
            ? new HttpClient()
            : new HttpClient(new HttpClientHandler { Proxy = minioClient.Proxy });
        minioClient.HttpClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", minioClient.FullUserAgent);
        return minioClient;
    }

    internal static Uri GetBaseUrl(string endpoint)
    {
        if (string.IsNullOrEmpty(endpoint))
            throw new ArgumentException(
                string.Format("{0} is the value of the endpoint. It can't be null or empty.", endpoint),
                nameof(endpoint));

        if (endpoint.EndsWith("/", StringComparison.OrdinalIgnoreCase))
            endpoint = endpoint.Substring(0, endpoint.Length - 1);
        if (!BuilderUtil.IsValidHostnameOrIPAddress(endpoint))
            throw new InvalidEndpointException(string.Format("{0} is invalid hostname.", endpoint), "endpoint");
        string conn_url;
        if (endpoint.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            throw new InvalidEndpointException(
                string.Format("{0} the value of the endpoint has the scheme (http/https) in it.", endpoint),
                "endpoint");

        var enable_https = Environment.GetEnvironmentVariable("ENABLE_HTTPS");
        var scheme = enable_https?.Equals("1", StringComparison.OrdinalIgnoreCase) == true ? "https://" : "http://";
        conn_url = scheme + endpoint;
        var url = new Uri(conn_url);
        var hostnameOfUri = url.Authority;
        if (!string.IsNullOrEmpty(hostnameOfUri) && !BuilderUtil.IsValidHostnameOrIPAddress(hostnameOfUri))
            throw new InvalidEndpointException(string.Format("{0}, {1} is invalid hostname.", endpoint, hostnameOfUri),
                "endpoint");

        return url;
    }

    internal static void SetBaseURL(this IMinioClient minioClient, Uri url)
    {
        if (url.IsDefaultPort)
            minioClient.BaseUrl = url.Host;
        else
            minioClient.BaseUrl = url.Host + ":" + url.Port;
    }
}