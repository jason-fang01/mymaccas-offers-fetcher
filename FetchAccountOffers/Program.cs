namespace MyMaccasOffersFetcher
{
    using FetchAccountOffers;
    using System.Text;
    using System.Text.Json;
    using System.Text.RegularExpressions;
    using System.Diagnostics;
    using Google.Apis.Auth.OAuth2;
    using Google.Apis.Gmail.v1;
    using Google.Apis.Gmail.v1.Data;
    using Google.Apis.Services;
    using Google.Apis.Util;
    using Google.Apis.Util.Store;
    using Serilog;

    class Program
    {
        private const int MAGIC_LINK_WAIT_DELAY = 12000;
        private const int SIGNIN_RETRY_BASE_DELAY = 2500;
        private const int API_SEMAPHORE_COUNT = 5;

        static async Task Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .WriteTo.Console()
                .WriteTo.File("logs/log-.txt", rollingInterval: RollingInterval.Day)
                .Enrich.FromLogContext()
                .CreateLogger();

            try
            {
                await RunApp(args);
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Application terminated unexpectedly");
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }

        static async Task RunApp(string[] args)
        {
            var stopwatch = Stopwatch.StartNew();
            var failedAccounts = new HashSet<string>();

            try
            {
                Log.Information("Application started at {StartTime}", DateTime.Now);
                Log.Information("Current delay settings:");
                Log.Information("MAGIC_LINK_WAIT_DELAY: {MagicLinkWaitDelay}ms", MAGIC_LINK_WAIT_DELAY);
                Log.Information("SIGNIN_RETRY_BASE_DELAY: {SigninRetryBaseDelay}ms", SIGNIN_RETRY_BASE_DELAY);

                var config = ConfigLoader.LoadConfig();
                var credential = await GetOrRefreshCredential(config);
                var gmailService = new GmailService(new BaseClientService.Initializer()
                {
                    HttpClientInitializer = credential,
                    ApplicationName = "MyMaccasOffersFetcher",
                });
                Log.Information("Configuration loaded successfully.");

                using var client = new HttpClient();
                Log.Information("HTTP client initialized.");

                var results = await ProcessEmails(config, client, failedAccounts);

                Log.Information("All emails processed.");

                foreach (var (email, offers) in results)
                {
                    if (offers != null)
                    {
                        DisplayOffersForAccount(email, offers);
                    }
                    else
                    {
                        Log.Warning("No offers found for {Email}", email);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "An error occurred");
            }
            finally
            {
                stopwatch.Stop();
                Log.Information("Application ended at {EndTime}", DateTime.Now);
                Log.Information("Total execution time: {ExecutionTime}", stopwatch.Elapsed);

                Log.Information("Summary of failed accounts:");
                if (failedAccounts.Count > 0)
                {
                    foreach (var account in failedAccounts)
                    {
                        Log.Warning("Failed account: {Account}", account);
                    }
                    Log.Warning("Total failed accounts: {FailedAccountsCount}", failedAccounts.Count);
                }
                else
                {
                    Log.Information("All accounts processed successfully.");
                }
            }
        }

        private static async Task<List<(string Email, OfferResponse Offers)>> ProcessEmails(Config config, HttpClient client, HashSet<string> failedAccounts)
        {
            var results = new List<(string Email, OfferResponse Offers)>();
            var tasks = config.EmailAliases.Select(email => ProcessSingleEmail(email, config, client, failedAccounts)).ToList();

            while (tasks.Any())
            {
                var completedTask = await Task.WhenAny(tasks);
                tasks.Remove(completedTask);
                results.Add(await completedTask);
            }

            return results;
        }

        private static SemaphoreSlim apiSemaphore = new SemaphoreSlim(API_SEMAPHORE_COUNT, API_SEMAPHORE_COUNT);

        private static async Task<(string Email, OfferResponse Offers)> ProcessSingleEmail(string email, Config config, HttpClient clientFactory, HashSet<string> failedAccounts)
        {
            await apiSemaphore.WaitAsync();
            try
            {
                Log.Information("Processing email: {Email}", email);
                var gmailService = GetGmailService(config);

                using var client = new HttpClient();

                var accessToken = await GetAccessToken(client, config);

                if (string.IsNullOrEmpty(accessToken))
                {
                    Log.Warning("No token retrieved for {Email}. Skipping.", email);
                    failedAccounts.Add(email);
                    return (email, (OfferResponse)null);
                }

                var sendMagicLinkResult = await SendMagicLinkLogin(client, config, accessToken, email);
                Log.Information("Magic link login request sent for {Email}.", email);

                Log.Information("Waiting for magic link email for {Email}...", email);
                var code = await GetLatestMagicLinkCode(gmailService, email);
                if (string.IsNullOrEmpty(code))
                {
                    Log.Error("Failed to get magic link code for {Email}. Skipping.", email);
                    failedAccounts.Add(email);
                    return (email, (OfferResponse)null);
                }

                var newAccessToken = await SigninWithCode(client, config, accessToken, code, email);
                if (string.IsNullOrEmpty(newAccessToken))
                {
                    Log.Error("Failed to sign in with the magic link code for {Email}.", email);
                    failedAccounts.Add(email);
                    return (email, (OfferResponse)null);
                }

                Log.Information("Successfully signed in with magic link code for {Email}.", email);

                var offers = await FetchOffers(client, config, newAccessToken);
                Log.Information("Finished processing email: {Email}", email);

                return (email, offers);
            }
            finally
            {
                apiSemaphore.Release();
            }
        }

        private static string GetTimestampedFilename()
        {
            string directory = "logs";
            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }
            return Path.Combine(directory, $"log_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
        }

        private static async Task<string?> GetAccessToken(HttpClient client, Config config)
        {
            var url = config.AuthTokenUrl;
            var content = new StringContent("grantType=client_credentials", Encoding.UTF8, "application/x-www-form-urlencoded");

            var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Content = content;

            request.Headers.Add("mcd-clientid", config.McdClientId);
            request.Headers.Add("authorization", $"Basic {config.McdBasicAuth}");
            request.Headers.Add("mcd-clientsecret", config.McdClientSecret);
            request.Headers.Add("cache-control", "true");
            request.Headers.Add("accept-charset", "UTF-8");
            request.Headers.Add("user-agent", config.UserAgent);
            request.Headers.Add("accept-language", "en-AU");
            request.Headers.Add("mcd-sourceapp", config.McdSourceApp);
            request.Headers.Add("mcd-uuid", "");
            request.Headers.Add("mcd-marketid", config.McdMarketId);

            try
            {
                var response = await client.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
                    var jsonResponse = await response.Content.ReadAsStringAsync();
                    var options = new JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true
                    };

                    var tokenInfo = JsonSerializer.Deserialize<TokenResponse>(jsonResponse, options);
                    return tokenInfo?.Response?.Token;
                }
                else
                {
                    Log.Error("Failed to retrieve token. Status code: {StatusCode}", response.StatusCode);
                    return null;
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Exception occurred while retrieving token");
                return null;
            }
        }

        private static async Task<HttpResponseMessage> SendMagicLinkLogin(HttpClient client, Config config, string token, string email)
        {
            var url = config.MagicLinkLoginUrl;
            var data = new
            {
                customerIdentifier = email,
                deviceId = config.DeviceId,
                registrationType = "traditional"
            };
            var content = new StringContent(JsonSerializer.Serialize(data), Encoding.UTF8, "application/json");
            var request = new HttpRequestMessage(HttpMethod.Post, url);

            request.Headers.Add("accept-charset", "UTF-8");
            request.Headers.Add("accept-language", "en-AU");
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            request.Headers.Add("cache-control", "true");
            request.Headers.Add("mcd-clientid", config.McdClientId);
            request.Headers.Add("mcd-marketid", config.McdMarketId);
            request.Headers.Add("mcd-sourceapp", config.McdSourceApp);
            request.Headers.Add("mcd-uuid", Guid.NewGuid().ToString());
            request.Headers.Add("user-agent", config.UserAgent);

            request.Content = content;

            return await client.SendAsync(request);
        }

        private static readonly InMemoryDataStore _dataStore = new InMemoryDataStore();

        private static readonly string CredentialPath = "token.json";

        private static GmailService GetGmailService(Config config)
        {
            UserCredential credential;
            using (var stream = new FileStream("client_secret.json", FileMode.Open, FileAccess.Read))
            {
                credential = GoogleWebAuthorizationBroker.AuthorizeAsync(
                    GoogleClientSecrets.Load(stream).Secrets,
                    config.GmailScopes,
                    "user",
                    CancellationToken.None,
                    new FileDataStore(CredentialPath, true)).Result;
            }

            return new GmailService(new BaseClientService.Initializer()
            {
                HttpClientInitializer = credential,
                ApplicationName = "MyMaccasOffersFetcher",
            });
        }
        private static async Task<UserCredential> GetOrRefreshCredential(Config config)
        {
            try
            {
                UserCredential credential;
                using (var stream = new FileStream("client_secret.json", FileMode.Open, FileAccess.Read))
                {
                    credential = await GoogleWebAuthorizationBroker.AuthorizeAsync(
                        GoogleClientSecrets.Load(stream).Secrets,
                        config.GmailScopes,
                        "user",
                        CancellationToken.None,
                        new FileDataStore(CredentialPath, true));
                }

                if (credential.Token.IsExpired(SystemClock.Default))
                {
                    await credential.RefreshTokenAsync(CancellationToken.None);
                }

                return credential;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error refreshing token: {ex.Message}");
                Console.WriteLine("Please re-authorize the application.");
                File.Delete(CredentialPath);
                return await GetOrRefreshCredential(config);
            }
        }

        private static async Task<string?> GetLatestMagicLinkCode(GmailService service, string alias)
        {
            try
            {
                await Task.Delay(MAGIC_LINK_WAIT_DELAY);

                var query = $"from:accounts@au.mcdonalds.com to:{alias}";
                var listRequest = service.Users.Messages.List("me");
                listRequest.Q = query;
                listRequest.MaxResults = 20;

                var response = await listRequest.ExecuteAsync();
                if (response.Messages == null || response.Messages.Count == 0)
                {
                    Log.Warning("No emails found for {Alias}", alias);
                    return null;
                }

                DateTime cutoffTime = DateTime.Now.AddMinutes(-10);
                string? latestCode = null;
                DateTime latestEmailTime = DateTime.MinValue;
                string? latestEmailId = null;

                foreach (var messageData in response.Messages)
                {
                    var message = await service.Users.Messages.Get("me", messageData.Id).ExecuteAsync();

                    long timestamp = long.Parse(message.InternalDate.ToString());
                    DateTime emailTime = DateTimeOffset.FromUnixTimeMilliseconds(timestamp).LocalDateTime;

                    if (emailTime < cutoffTime)
                    {
                        Log.Debug("Skipping old email for {Alias} from {EmailTime}", alias, emailTime);
                        continue;
                    }

                    if (emailTime > latestEmailTime)
                    {
                        string? code = ExtractMagicLinkCode(message);
                        if (code != null)
                        {
                            latestCode = code;
                            latestEmailTime = emailTime;
                            latestEmailId = messageData.Id;
                            Log.Debug("Found newer magic link for {Alias} from {LatestEmailTime}", alias, latestEmailTime);
                        }
                    }
                }

                if (latestCode != null && latestEmailId != null)
                {
                    Log.Information("Using magic link for {Alias} from {LatestEmailTime}", alias, latestEmailTime);
                    await DeleteEmail(service, latestEmailId);
                    return latestCode;
                }
                else
                {
                    Log.Warning("No valid recent magic link found for {Alias}", alias);
                    return null;
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error in GetLatestMagicLinkCode for {Alias}", alias);
                return null;
            }
        }

        private static async Task DeleteEmail(GmailService service, string emailId)
        {
            try
            {
                await service.Users.Messages.Trash("me", emailId).ExecuteAsync();
                Log.Information("Successfully deleted email with ID: {EmailId}", emailId);
            }
            catch (Google.GoogleApiException ex) when (ex.HttpStatusCode == System.Net.HttpStatusCode.Forbidden)
            {
                Log.Error("Error: Insufficient permissions to delete the email. Please check Gmail API scopes.");
                Log.Information("Continuing without deleting the email.");
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Unexpected error deleting email");
                Log.Information("Continuing without deleting the email.");
            }
        }

        private static string? ExtractMagicLinkCode(Message message)
        {
            if (message.Payload?.Body?.Data == null)
            {
                Log.Warning("Email body is empty or null");
                return null;
            }

            string rawContent = message.Payload.Body.Data;
            byte[] data = Convert.FromBase64String(rawContent.Replace('-', '+').Replace('_', '/'));
            string decodedString = Encoding.UTF8.GetString(data);

            var pattern = @"html%3Fml=([^=]+)";
            var match = Regex.Match(decodedString, pattern);

            if (match.Success)
            {
                return match.Groups[1].Value;
            }
            else
            {
                Log.Warning("Magic link code not found in the email content");
                return null;
            }
        }

        private static async Task<string?> SigninWithCode(HttpClient client, Config config, string token, string code, string email)
        {
            const int maxAttempts = 2;
            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                try
                {
                    Log.Information("Attempt {Attempt} to sign in for {Email}", attempt, email);

                    token = await GetAccessToken(client, config);
                    if (string.IsNullOrEmpty(token))
                    {
                        Log.Warning("Failed to refresh token for {Email}", email);
                        continue;
                    }

                    var result = await SigninWithCodeAttempt(client, config, token, code);
                    if (!string.IsNullOrEmpty(result))
                    {
                        return result;
                    }
                    else
                    {
                        Log.Warning("Signin attempt {Attempt} for {Email} returned null result", attempt, email);
                    }
                }
                catch (HttpRequestException ex)
                {
                    Log.Error(ex, "HTTP error during signin attempt {Attempt} for {Email}", attempt, email);
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Unexpected error during signin attempt {Attempt} for {Email}", attempt, email);
                }

                if (attempt < maxAttempts)
                {
                    int delay = (int)Math.Pow(2, attempt) * SIGNIN_RETRY_BASE_DELAY;
                    Log.Information("Retrying signin for {Email} in {Delay}ms...", email, delay);
                    await Task.Delay(delay);
                }
            }

            Log.Error("Failed to sign in after {MaxAttempts} attempts for {Email}.", maxAttempts, email);
            return null;
        }

        private static async Task<string?> SigninWithCodeAttempt(HttpClient client, Config config, string token, string code)
        {
            var url = config.SigninWithCodeUrl;
            var payload = new
            {
                activationLink = code,
                clientInfo = new
                {
                    device = new
                    {
                        deviceUniqueId = config.DeviceId,
                        os = config.DeviceOs,
                        osVersion = config.DeviceOsVersion
                    }
                }
            };

            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

            var request = new HttpRequestMessage(HttpMethod.Put, url);
            request.Content = content;

            request.Headers.Add("mcd-clientid", config.McdClientId);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            request.Headers.Add("cache-control", "true");
            request.Headers.Add("accept-charset", "UTF-8");
            request.Headers.Add("user-agent", config.UserAgent);
            request.Headers.Add("accept-language", "en-AU");
            request.Headers.Add("mcd-sourceapp", config.McdSourceApp);
            request.Headers.Add("mcd-uuid", Guid.NewGuid().ToString());
            request.Headers.Add("mcd-marketid", config.McdMarketId);

            Log.Information("Sending sign-in request to: {Url}", url);

            var response = await client.SendAsync(request);

            Log.Information("Response status code: {StatusCode}", response.StatusCode);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var signinResponse = JsonSerializer.Deserialize<SigninResponse>(responseContent);
                return signinResponse?.Response?.AccessToken;
            }
            else
            {
                Log.Error("Failed to sign in: {StatusCode}", response.StatusCode);
                return null;
            }
        }


        private static async Task<OfferResponse> FetchOffers(HttpClient client, Config config, string token)
        {
            var url = config.OffersUrl;
            var queryString = $"distance={config.OfferDistance}&latitude={config.OfferLatitude}&longitude={config.OfferLongitude}&optOuts=&timezoneOffsetInMinutes={config.OfferTimezoneOffset}";

            var request = new HttpRequestMessage(HttpMethod.Get, $"{url}?{queryString}");

            foreach (var header in config.CommonHeaders)
            {
                request.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            var response = await client.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                var jsonResponse = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<OfferResponse>(jsonResponse);
            }
            else
            {
                Log.Error("Failed to fetch offers: {StatusCode}", response.StatusCode);
                return null;
            }
        }

        private static void DisplayOffersForAccount(string email, OfferResponse offers)
        {
            var separator = new string('-', 40);
            Log.Information("{Separator}", separator);
            Log.Information("Offers for account: {Email}", email);
            Log.Information("{Separator}", separator);

            if (offers?.Response?.Offers != null && offers.Response.Offers.Any())
            {
                foreach (var offer in offers.Response.Offers)
                {
                    Log.Information("{OfferName}", offer.Name);
                    Log.Information("Description: {OfferDescription}", offer.ShortDescription);
                    Log.Information("Valid: {ValidFrom} to {ValidTo}",
                        offer.LocalValidFrom,
                        offer.LocalValidTo);
                    Log.Information("{Separator}", separator);
                }
            }
            else
            {
                Log.Warning("No offers found for {Email}", email);
            }

            Log.Information("");
        }
    }
}
