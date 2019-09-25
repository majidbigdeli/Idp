using IdentityServer4.Models;
using Manex.Authentication.Context;
using Manex.Authentication.Entities.Identity;
using System;
using System.Linq;
using WebIddentityServer4.Models;

namespace WebIddentityServer4.Repositories
{
    public class AccountRepository : IAccountRepository
    {
        private ApplicationDbContext _db;

        public AccountRepository(ApplicationDbContext context)
        {
            _db = context;
        }

        public User GetUser(string username, string password)
        {

            return null; 
           // return _db.Users.FirstOrDefault(m => m.UserName == username && m.PasswordHash == password.Sha256());
        }

        public void InsertUser(string username, string password, string phone, out Guid userGuid)
        {
            userGuid = Guid.NewGuid();
            //_db.Users.Add(new User()
            //{
            //    UserGuid = userGuid,
            //    Username = username,
            //    EncryptedPassword = password.Sha256(),
            //    Phone = phone
            //});
            //_db.SaveChanges();
        }
    }

}
