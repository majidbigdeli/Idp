﻿using DNTPersianUtils.Core;
using Manex.Authentication.GuardToolkit;
using Manex.Authentication.PersianToolkit;
using Microsoft.AspNetCore.Identity;
using System;
using System.Linq;

namespace Manex.Authentication.Services.Identity
{
    /// <summary>
    /// More info: http://www.dotnettips.info/post/2579
    /// </summary>
    public class CustomNormalizer : ILookupNormalizer
    {
        public string Normalize(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                return null;
            }

            key = key.Trim();

            if (key.IsEmailAddress())
            {
                key = fixGmailDots(key);
            }
            else
            {
                key = key.ApplyCorrectYeKe()
                     .RemoveDiacritics()
                     .CleanUnderLines()
                     .RemovePunctuation();
                key = key.Trim().Replace(" ", "");
            }

            key = key.ToUpperInvariant();
            return key;
        }

        private static string fixGmailDots(string email)
        {
            email = email.ToLowerInvariant().Trim();
            var emailParts = email.Split('@');
            var name = emailParts[0].Replace(".", string.Empty);

            var plusIndex = name.IndexOf("+", StringComparison.OrdinalIgnoreCase);
            if (plusIndex != -1)
            {
                name = name.Substring(0, plusIndex);
            }

            var emailDomain = emailParts[1];
            emailDomain = emailDomain.Replace("googlemail.com", "gmail.com");

            string[] domainsAllowedDots =
            {
                "gmail.com",
                "facebook.com"
            };

            var isFromDomainsAllowedDots = domainsAllowedDots.Any(domain => emailDomain.Equals(domain));
            return !isFromDomainsAllowedDots ? email : string.Format("{0}@{1}", name, emailDomain);
        }
    }
}