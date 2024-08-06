namespace MyMaccasOffersFetcher
{
    using FetchAccountOffers;
    using Google.Apis.Auth.OAuth2;
    using Google.Apis.Gmail.v1;
    using Google.Apis.Services;
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
                    Console.WriteLine("Configuration loaded successfully.");

                    using var client = new HttpClient();
                    var gmailService = GetGmailService(config);
                    Console.WriteLine("Gmail service initialized.");

                    await ProcessEmails(config, client, gmailService);

                    Console.WriteLine("\nAll emails processed.");
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

        private static async Task ProcessEmails(Config config, HttpClient client, GmailService gmailService)
        {
            foreach (var email in config.EmailAliases)
            {
                Console.WriteLine($"\nProcessing email: {email}");

                var accessToken = await GetAccessToken(client, config);
                if (string.IsNullOrEmpty(accessToken))
                {
                    Console.WriteLine("No token retrieved. Skipping this email.");
                    continue;
                }

                var sendMagicLinkResult = await SendMagicLinkLogin(client, config, accessToken, email);
                Console.WriteLine("Magic link login request sent.");

                Console.WriteLine("Waiting for magic link email...");
                var code = await GetLatestMagicLinkCode(gmailService, email);
                if (string.IsNullOrEmpty(code))
                {
                    Console.WriteLine($"Failed to get magic link code for {email}. Skipping.");
                    continue;
                }

                var newAccessToken = await SigninWithCode(client, config, accessToken, code);
                if (string.IsNullOrEmpty(newAccessToken))
                {
                    Console.WriteLine("Failed to sign in with the magic link code.");
                    continue;
                }

                Console.WriteLine("Successfully signed in with magic link code.");

                var offers = await FetchOffers(client, config, newAccessToken);
                if (offers != null)
                {
                    DisplayOffersForAccount(email, offers);
                }
                else
                {
                    Console.WriteLine($"No offers found for {email}");
                }

                Console.WriteLine($"Finished processing email: {email}");

                await Task.Delay(2000);
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

            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("mcd-clientid", config.McdClientId);
            client.DefaultRequestHeaders.Add("authorization", $"Basic {config.McdBasicAuth}");
            client.DefaultRequestHeaders.Add("mcd-clientsecret", config.McdClientSecret);
            client.DefaultRequestHeaders.Add("cache-control", "true");
            client.DefaultRequestHeaders.Add("accept-charset", "UTF-8");
            client.DefaultRequestHeaders.Add("user-agent", config.UserAgent);
            client.DefaultRequestHeaders.Add("accept-language", "en-AU");
            client.DefaultRequestHeaders.Add("mcd-sourceapp", config.McdSourceApp);
            client.DefaultRequestHeaders.Add("mcd-uuid", "");
            client.DefaultRequestHeaders.Add("mcd-marketid", config.McdMarketId);

            try
            {
                var response = await client.PostAsync(url, content);

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

            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("accept-charset", "UTF-8");
            client.DefaultRequestHeaders.Add("accept-language", "en-AU");
            client.DefaultRequestHeaders.Add("authorization", $"Bearer {token}");
            client.DefaultRequestHeaders.Add("cache-control", "true");
            client.DefaultRequestHeaders.Add("mcd-clientid", config.McdClientId);
            client.DefaultRequestHeaders.Add("mcd-marketid", config.McdMarketId);
            client.DefaultRequestHeaders.Add("mcd-sourceapp", config.McdSourceApp);
            client.DefaultRequestHeaders.Add("mcd-uuid", Guid.NewGuid().ToString());
            client.DefaultRequestHeaders.Add("user-agent", config.UserAgent);

            return await client.PostAsync(url, content);
        }

        private static GmailService GetGmailService(Config config)
        {
            UserCredential credential;
            using (var stream = new FileStream("client_secret.json", FileMode.Open, FileAccess.Read))
            {
                string credPath = "token.json";
                credential = GoogleWebAuthorizationBroker.AuthorizeAsync(
                    GoogleClientSecrets.Load(stream).Secrets,
                    config.GmailScopes,
                    "user",
                    CancellationToken.None,
                    new FileDataStore(credPath, true)).Result;
            }

            return new GmailService(new BaseClientService.Initializer()
            {
                HttpClientInitializer = credential,
                ApplicationName = "MyMaccasOffersFetcher",
            });
        }

        private static async Task<string?> GetLatestMagicLinkCode(GmailService service, string alias)
        {
            try
            {
                await Task.Delay(8000);

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

        private static async Task<string?> SigninWithCode(HttpClient client, Config config, string token, string code)
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

            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("mcd-clientid", config.McdClientId);
            client.DefaultRequestHeaders.Add("authorization", $"Bearer {token}");
            client.DefaultRequestHeaders.Add("cache-control", "true");
            client.DefaultRequestHeaders.Add("accept-charset", "UTF-8");
            client.DefaultRequestHeaders.Add("user-agent", config.UserAgent);
            client.DefaultRequestHeaders.Add("accept-language", "en-AU");
            client.DefaultRequestHeaders.Add("mcd-sourceapp", config.McdSourceApp);
            client.DefaultRequestHeaders.Add("mcd-uuid", Guid.NewGuid().ToString());
            client.DefaultRequestHeaders.Add("mcd-marketid", config.McdMarketId);

            var response = await client.PutAsync(url, content);

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

            client.DefaultRequestHeaders.Clear();
            foreach (var header in config.CommonHeaders)
            {
                client.DefaultRequestHeaders.TryAddWithoutValidation(header.Key, header.Value);
            }
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            var response = await client.GetAsync($"{url}?{queryString}");

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
