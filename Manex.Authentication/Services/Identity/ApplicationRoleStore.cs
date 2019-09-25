using Manex.Authentication.Context;
using Manex.Authentication.Contracts.Identity;
using Manex.Authentication.Entities.Identity;
using Manex.Authentication.GuardToolkit;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using System.Security.Claims;

namespace Manex.Authentication.Services.Identity
{
    /// <summary>
    /// More info: http://www.dotnettips.info/post/2578
    /// </summary>
    public class ApplicationRoleStore :
        RoleStore<Role, ApplicationDbContext, long, UserRole, RoleClaim>,
        IApplicationRoleStore
    {
        private readonly IUnitOfWork _uow;
        private readonly IdentityErrorDescriber _describer;

        public ApplicationRoleStore(
            IUnitOfWork uow,
            IdentityErrorDescriber describer)
            : base((ApplicationDbContext)uow, describer)
        {
            _uow = uow;
            _uow.CheckArgumentIsNull(nameof(_uow));

            _describer = describer;
            _describer.CheckArgumentIsNull(nameof(_describer));
        }


        #region BaseClass

        protected override RoleClaim CreateRoleClaim(Role role, Claim claim)
        {
            return new RoleClaim
            {
                RoleId = role.Id,
                ClaimType = claim.Type,
                ClaimValue = claim.Value
            };
        }

        #endregion

        #region CustomMethods

        #endregion
    }
}