using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Manex.Authentication.Utility
{
    static class SmsMessageKavehnegar
    {
        private static HttpClient _client;
        private const string Signature = "786D6C625271496C705557543233706C325764314D2B693032742B484757674B";
        private const string SenderLine = "10007070000700";
        
        static SmsMessageKavehnegar()
        {
            _client = new HttpClient { BaseAddress = new Uri("https://api.kavenegar.com/") };
            _client.DefaultRequestHeaders.Accept.Clear();
        }

        public static bool SendToken(string receptor, List<string> token, string template = "manexotp", string verifier = "Api", int? UserId = null)
        {
            var number2 = receptor;
            if (receptor.StartsWith("0"))
            {
                number2 = receptor.Substring(1);
            }
            if (number2.Length == 10)
            {
                receptor = "98" + number2;
            }
            string tok = "";
            for (int i = 0; i < token.Count; i++)
            {
                tok += $"token{(i > 0 ? (i + 1).ToString() : "")}={token[i]}&";
            }
            string message = $"v1/{Signature}/verify/lookup.json?receptor={receptor}&{tok}template={template}";
            string messageStr = $"{tok}template={template}";
            var response = _client.GetAsync(message).Result;
            if (response.IsSuccessStatusCode)
            {
                var respdata = response.Content.ReadAsStringAsync().Result;
                var respModel = KavehNegarSmsResponse.FromJson(respdata);

                if (respModel.Return.Status == 200)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            return true;
            
        }
    }

    #region Response Classes
    public partial class KavehNegarSmsResponse
    {
        [JsonProperty("return")]
        public Return Return { get; set; }

        [JsonProperty("entries")]
        public List<Entry> Entries { get; set; }
    }
    public partial class KavehNegarSmsResponse
    {
        public static KavehNegarSmsResponse FromJson(string json) => JsonConvert.DeserializeObject<KavehNegarSmsResponse>(json, Settings);
        public static readonly JsonSerializerSettings Settings = new JsonSerializerSettings
        {
            MetadataPropertyHandling = MetadataPropertyHandling.Ignore,
            DateParseHandling = DateParseHandling.None,
            Converters = {
                new IsoDateTimeConverter { DateTimeStyles = DateTimeStyles.AssumeUniversal }
            },
        };
    }
    public partial class Entry
    {
        [JsonProperty("messageid")]
        public long Messageid { get; set; }

        [JsonProperty("message")]
        public string Message { get; set; }

        [JsonProperty("status")]
        public long Status { get; set; }

        [JsonProperty("statustext")]
        public string Statustext { get; set; }

        [JsonProperty("sender")]
        public string Sender { get; set; }

        [JsonProperty("receptor")]
        public string Receptor { get; set; }

        [JsonProperty("date")]
        public long Date { get; set; }

        [JsonProperty("cost")]
        public long Cost { get; set; }
    }
    public partial class Return
    {
        [JsonProperty("status")]
        public long Status { get; set; }

        [JsonProperty("message")]
        public string Message { get; set; }
    }
    #endregion
    
}