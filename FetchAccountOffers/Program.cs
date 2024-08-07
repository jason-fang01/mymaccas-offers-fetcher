namespace MyMaccasOffersFetcher
{
    using FetchAccountOffers;
    using Google.Apis.Auth.OAuth2;
    using Google.Apis.Gmail.v1;
    using Google.Apis.Services;
    using Google.Apis.Util;
    using Google.Apis.Util.Store;
    using System.Text;
    using System.Text.Json;
    using System.Text.RegularExpressions;

    class Program
    {
        static async Task Main(string[] args)
        {
            string logFilename = GetTimestampedFilename();

            using (var writer = new ConsoleAndFileWriter(logFilename))
            {
                Console.SetOut(writer);

                try
                {
                    Console.WriteLine($"Application started at {DateTime.Now}");

                    var config = ConfigLoader.LoadConfig();
                    var credential = await GetOrRefreshCredential(config);
                    var gmailService = new GmailService(new BaseClientService.Initializer()
                    {
                        HttpClientInitializer = credential,
                        ApplicationName = "MyMaccasOffersFetcher",
                    });
                    Console.WriteLine("Configuration loaded successfully.");

                    using var client = new HttpClient();
                    Console.WriteLine("HTTP client initialized.");

                    var results = await ProcessEmails(config, client);

                    Console.WriteLine("\nAll emails processed.");

                    foreach (var (email, offers) in results)
                    {
                        if (offers != null)
                        {
                            DisplayOffersForAccount(email, offers);
                        }
                        else
                        {
                            Console.WriteLine($"No offers found for {email}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"An error occurred: {ex.Message}");
                    Console.WriteLine($"Stack Trace: {ex.StackTrace}");
                }
                finally
                {
                    Console.WriteLine($"\nApplication ended at {DateTime.Now}");
                }
            }
        }

        private static async Task<List<(string Email, OfferResponse Offers)>> ProcessEmails(Config config, HttpClient client)
        {
            var results = new List<(string Email, OfferResponse Offers)>();
            foreach (var batch in config.EmailAliases.Chunk(5))
            {
                var batchTasks = batch.Select(email => ProcessSingleEmail(email, config, client));
                var batchResults = await Task.WhenAll(batchTasks);
                results.AddRange(batchResults);
                await Task.Delay(8000);
            }
            return results;
        }

        private static async Task<(string Email, OfferResponse Offers)> ProcessSingleEmail(string email, Config config, HttpClient clientFactory)
        {
            Console.WriteLine($"\nProcessing email: {email}");
            var gmailService = GetGmailService(config);

            using var client = new HttpClient();

            var accessToken = await GetAccessToken(client, config);

            if (string.IsNullOrEmpty(accessToken))
            {
                Console.WriteLine($"No token retrieved for {email}. Skipping.");
                return (email, (OfferResponse)null);
            }

            var sendMagicLinkResult = await SendMagicLinkLogin(client, config, accessToken, email);
            Console.WriteLine($"Magic link login request sent for {email}.");

            Console.WriteLine($"Waiting for magic link email for {email}...");
            var code = await GetLatestMagicLinkCode(gmailService, email);
            if (string.IsNullOrEmpty(code))
            {
                Console.WriteLine($"Failed to get magic link code for {email}. Skipping.");
                return (email, (OfferResponse)null);
            }

            var newAccessToken = await SigninWithCode(client, config, accessToken, code, email);
            if (string.IsNullOrEmpty(newAccessToken))
            {
                Console.WriteLine($"Failed to sign in with the magic link code for {email}.");
                return (email, (OfferResponse)null);
            }

            Console.WriteLine($"Successfully signed in with magic link code for {email}.");

            var offers = await FetchOffers(client, config, newAccessToken);
            Console.WriteLine($"Finished processing email: {email}");

            return (email, offers);
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
                    Console.WriteLine($"Failed to retrieve token. Status code: {response.StatusCode}");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception occurred while retrieving token: {ex.Message}");
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
                await Task.Delay(5000);

                var query = $"from:accounts@au.mcdonalds.com to:{alias}";
                var listRequest = service.Users.Messages.List("me");
                listRequest.Q = query;
                listRequest.MaxResults = 1;

                var response = await listRequest.ExecuteAsync();
                if (response.Messages == null || response.Messages.Count == 0)
                {
                    Console.WriteLine($"No emails found for {alias}");
                    return null;
                }

                var latestEmailId = response.Messages[0].Id;
                var message = await service.Users.Messages.Get("me", latestEmailId).ExecuteAsync();

                if (message.Payload?.Body?.Data == null)
                {
                    Console.WriteLine("Email body is empty or null");
                    return null;
                }

                string rawContent = message.Payload.Body.Data;
                byte[] data;
                try
                {
                    data = Convert.FromBase64String(rawContent.Replace('-', '+').Replace('_', '/'));
                }
                catch (FormatException)
                {
                    Console.WriteLine("Failed to decode Base64 content. The content might not be Base64 encoded.");
                    data = Encoding.UTF8.GetBytes(rawContent);
                }

                string decodedString = Encoding.UTF8.GetString(data);

                var pattern = @"html%3Fml=([^=]+)";
                var match = Regex.Match(decodedString, pattern);

                if (match.Success)
                {
                    return match.Groups[1].Value;
                }
                else
                {
                    Console.WriteLine("Magic link code not found in the email content");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in GetLatestMagicLinkCode: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                return null;
            }
        }

        private static async Task<string?> SigninWithCode(HttpClient client, Config config, string token, string code, string email)
        {
            const int maxAttempts = 3;
            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                try
                {
                    var result = await SigninWithCodeAttempt(client, config, token, code);
                    if (!string.IsNullOrEmpty(result))
                    {
                        return result;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Attempt {attempt} failed for {email}: {ex.Message}");
                }

                if (attempt < maxAttempts)
                {
                    int delay = attempt * 2000;
                    Console.WriteLine($"Retrying signin for {email} in {delay}ms...");
                    await Task.Delay(delay);
                }
            }

            Console.WriteLine($"Failed to sign in after {maxAttempts} attempts for {email}.");
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

            var response = await client.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var signinResponse = JsonSerializer.Deserialize<SigninResponse>(responseContent);
                return signinResponse?.Response?.AccessToken;
            }
            else
            {
                Console.WriteLine($"Failed to sign in: {response.StatusCode}");
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
                Console.WriteLine($"Failed to fetch offers: {response.StatusCode}");
                return null;
            }
        }

        private static void DisplayOffersForAccount(string email, OfferResponse offers)
        {
            var separator = new string('=', 80);
            var output = new StringBuilder();
            output.AppendLine(separator);
            output.AppendLine($"Offers for account: {email}");
            output.AppendLine(separator);
            output.AppendLine();

            if (offers?.Response?.Offers != null && offers.Response.Offers.Any())
            {
                for (int i = 0; i < offers.Response.Offers.Count; i++)
                {
                    var offer = offers.Response.Offers[i];
                    output.AppendLine($"Offer #{i + 1}:");
                    output.AppendLine($"  Name: {offer.Name ?? "N/A"}");
                    output.AppendLine($"  Description: {offer.ShortDescription ?? "N/A"}");
                    output.AppendLine($"  Valid From: {offer.LocalValidFrom ?? "N/A"}");
                    output.AppendLine($"  Valid To: {offer.LocalValidTo ?? "N/A"}");
                    output.AppendLine();
                }
            }
            else
            {
                output.AppendLine("No offers found or invalid data structure.");
            }

            output.AppendLine(separator);
            output.AppendLine();

            Console.WriteLine(output.ToString());
            File.AppendAllText("offers_output.txt", output.ToString());
        }
    }
}
