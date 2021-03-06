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

        public RegisterUserWithPassword(RegisterUserDto user, IApplicationUserManager applicationUserManager) {
            _user = user;
            _applicationUserManager = applicationUserManager;

        }
        public async Task<IdentityResult> Register() {
            var res = await _applicationUserManager.CreateAsync(new User {
                UserName = _user.Phone,
                FirstName = _user.FirstName,
                LastName = _user.LastName,
                Email = _user.Email,
                IsActive = true
            }, _user.Password);

            return res;
        }
    }

    public class RegisterUserWithoutPassword : IRegisterUserFactory {

        private readonly RegisterUserDto _user;
        private readonly IApplicationUserManager _applicationUserManager;
        public RegisterUserWithoutPassword(RegisterUserDto user, IApplicationUserManager applicationUserManager) {
            _user = user;
            _applicationUserManager = applicationUserManager;
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

            return result;
        }
    }

    public abstract class RegisterUserFactory {
        public abstract IRegisterUserFactory Create(RegisterUserDto user, IApplicationUserManager applicationUserManager);
    }

    public class RegisterUserWithPasswordFactory : RegisterUserFactory {
        public override IRegisterUserFactory Create(RegisterUserDto user, IApplicationUserManager applicationUserManager) => new RegisterUserWithPassword(user, applicationUserManager);
    }

    public class RegisterUserWithoutPasswordFactory : RegisterUserFactory {
        public override IRegisterUserFactory Create(RegisterUserDto user, IApplicationUserManager applicationUserManager) => new RegisterUserWithoutPassword(user, applicationUserManager);
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
