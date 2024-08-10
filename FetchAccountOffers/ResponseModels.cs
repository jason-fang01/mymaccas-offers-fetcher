namespace FetchAccountOffers
{
    using System.Text.Json.Serialization;

    public class SigninResponse
    {
        [JsonPropertyName("response")]
        public SigninResponseData Response { get; set; }
    }

    public class SigninResponseData
    {
        [JsonPropertyName("accessToken")]
        public string AccessToken { get; set; }
    }

    public class OfferResponse
    {
        [JsonPropertyName("response")]
        public OfferResponseData Response { get; set; }
    }

    public class OfferResponseData
    {
        [JsonPropertyName("offers")]
        public List<Offer> Offers { get; set; }
    }

    public class Offer
    {
        [JsonPropertyName("name")]
        public string Name { get; set; }

        [JsonPropertyName("shortDescription")]
        public string ShortDescription { get; set; }

        [JsonPropertyName("localValidFrom")]
        public string LocalValidFrom { get; set; }

        [JsonPropertyName("localValidTo")]
        public string LocalValidTo { get; set; }
    }

    public class LoyaltyPointsResponse
    {
        [JsonPropertyName("response")]
        public LoyaltyPointsData Response { get; set; }
    }

    public class LoyaltyPointsData
    {
        [JsonPropertyName("totalPoints")]
        public int TotalPoints { get; set; }

        [JsonPropertyName("lifeTimePoints")]
        public int LifeTimePoints { get; set; }
    }

    public class TokenResponse
    {
        [JsonPropertyName("status")]
        public Status Status { get; set; }

        [JsonPropertyName("response")]
        public TokenResponseData Response { get; set; }
    }

    public class Status
    {
        [JsonPropertyName("code")]
        public int Code { get; set; }

        [JsonPropertyName("type")]
        public string Type { get; set; }

        [JsonPropertyName("message")]
        public string Message { get; set; }
    }

    public class TokenResponseData
    {
        [JsonPropertyName("token")]
        public string Token { get; set; }

        [JsonPropertyName("expires")]
        public int Expires { get; set; }
    }
}
