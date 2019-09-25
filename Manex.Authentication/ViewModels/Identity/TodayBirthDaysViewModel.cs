using Manex.Authentication.Entities.Identity;
using System.Collections.Generic;

namespace Manex.Authentication.Identity
{
    public class TodayBirthDaysViewModel
    {
        public List<User> Users { set; get; }

        public AgeStatViewModel AgeStat { set; get; }
    }
}