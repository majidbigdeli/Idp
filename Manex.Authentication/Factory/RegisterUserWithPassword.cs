using Manex.Authentication.Contracts.Identity;
using Manex.Authentication.Entities.Identity;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Manex.Authentication.Factory {

    public interface IRegisterUserFactory {
        Task<IdentityResult> Register();
    }

    public class RegisterUserWithPassword : IRegisterUserFactory {

        private readonly RegisterUserDto _user;
        private readonly IApplicationUserManager _applicationUserManager;
        private readonly IApplicationRoleManager _applicationRoleManager;

        public RegisterUserWithPassword(RegisterUserDto user, IApplicationUserManager applicationUserManager, IApplicationRoleManager applicationRoleManager) {
            _user = user;
            _applicationUserManager = applicationUserManager;
            _applicationRoleManager = applicationRoleManager;
        }
        public async Task<IdentityResult> Register()
        {
            var user = new User
            {
                UserName = _user.Phone,
                FirstName = _user.FirstName,
                LastName = _user.LastName,
                Email = _user.Email,
                IsActive = true,
            };
            var res = await _applicationUserManager.CreateAsync(user, _user.Password);

            var role = await _applicationRoleManager.FindByNameAsync("User");
            var listRoleId = new List<long>();
            listRoleId.Add(role.Id);
            await _applicationUserManager.SetUserRole(user.Id, listRoleId);
            
            

            return res;
        }
    }

    public class RegisterUserWithoutPassword : IRegisterUserFactory {

        private readonly RegisterUserDto _user;
        private readonly IApplicationUserManager _applicationUserManager;
        private readonly IApplicationRoleManager _applicationRoleManager;
        public RegisterUserWithoutPassword(RegisterUserDto user, IApplicationUserManager applicationUserManager, IApplicationRoleManager applicationRoleManager) {
            _user = user;
            _applicationUserManager = applicationUserManager;
            _applicationRoleManager = applicationRoleManager;
        }

        public async Task<IdentityResult> Register() {
            var user = new User {
                UserName = _user.Phone,
                FirstName = _user.FirstName,
                LastName = _user.LastName,
                Email = _user.Email,
                IsActive = true
            };
            var result = await _applicationUserManager.CreateUserAsync(user);
            
            var role = await _applicationRoleManager.FindByNameAsync("User");
            var listRoleId = new List<long>();
            listRoleId.Add(role.Id);
            await _applicationUserManager.SetUserRole(user.Id, listRoleId);

            return result;
        }
    }

    public abstract class RegisterUserFactory {
        public abstract IRegisterUserFactory Create(RegisterUserDto user, IApplicationUserManager applicationUserManager,IApplicationRoleManager applicationRoleManager);
    }

    public class RegisterUserWithPasswordFactory : RegisterUserFactory {
        public override IRegisterUserFactory Create(RegisterUserDto user, IApplicationUserManager applicationUserManager,IApplicationRoleManager applicationRoleManager)
            => new RegisterUserWithPassword(user, applicationUserManager,applicationRoleManager);
    }

    public class RegisterUserWithoutPasswordFactory : RegisterUserFactory {
        public override IRegisterUserFactory Create(RegisterUserDto user, IApplicationUserManager applicationUserManager,IApplicationRoleManager applicationRoleManager)
            => new RegisterUserWithoutPassword(user, applicationUserManager,applicationRoleManager);
    }

    public class RegisterUserDto {

        [Required]
        public string Phone { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }

}
