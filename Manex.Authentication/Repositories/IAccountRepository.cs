using Manex.Authentication.Entities.Identity;
using System;
using WebIddentityServer4.Models;

namespace WebIddentityServer4.Repositories
{
    public interface IAccountRepository
    {
        User GetUser(string username, string password);

        void InsertUser(string username, string password, string phone, out Guid userGuid);
    }
}
