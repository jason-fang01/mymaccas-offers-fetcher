using Microsoft.Extensions.Configuration;

namespace FetchAccountOffers
{
    public class Config
    {
        public string AuthTokenUrl { get; set; }
        public string MagicLinkLoginUrl { get; set; }
        public string SigninWithCodeUrl { get; set; }
        public string OffersUrl { get; set; }
        public string LoyaltyPointsUrl { get; set; }
        public string McdClientId { get; set; }
        public string McdClientSecret { get; set; }
        public string McdBasicAuth { get; set; }
        public string McdSourceApp { get; set; }
        public string McdMarketId { get; set; }
        public string UserAgent { get; set; }
        public List<string> GmailScopes { get; set; }
        public string OfferDistance { get; set; }
        public string OfferLatitude { get; set; }
        public string OfferLongitude { get; set; }
        public string OfferTimezoneOffset { get; set; }
        public string DeviceId { get; set; }
        public string DeviceOs { get; set; }
        public string DeviceOsVersion { get; set; }
        public List<string> EmailAliases { get; set; }
        public SigninPayloadTemplate SigninPayloadTemplate { get; set; }
        public Dictionary<string, string> SigninHeaders { get; set; }
        public Dictionary<string, string> CommonHeaders { get; set; }
    }

    public class SigninPayloadTemplate
    {
        public string ActivationLink { get; set; }
        public ClientInfo ClientInfo { get; set; }
    }

    public class ClientInfo
    {
        public Device Device { get; set; }
    }

    public class Device
    {
        public string DeviceUniqueId { get; set; }
        public string Os { get; set; }
        public string OsVersion { get; set; }
    }

    public static class ConfigLoader
    {
        public static Config LoadConfig()
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("config.json", optional: false, reloadOnChange: true);

            IConfiguration configuration = builder.Build();

            var config = new Config();
            configuration.Bind(config);

            return config;
        }
    }

}
