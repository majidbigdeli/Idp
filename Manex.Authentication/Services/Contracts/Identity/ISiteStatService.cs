using Manex.Authentication.Entities.Identity;
using Manex.Authentication.Identity;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Manex.Authentication.Contracts.Identity
{
    public interface ISiteStatService
    {
        Task<List<User>> GetOnlineUsersListAsync(int numbersToTake, int minutesToTake);

        Task<List<User>> GetTodayBirthdayListAsync();

        Task UpdateUserLastVisitDateTimeAsync(ClaimsPrincipal claimsPrincipal);

        Task<AgeStatViewModel> GetUsersAverageAge();
    }
}