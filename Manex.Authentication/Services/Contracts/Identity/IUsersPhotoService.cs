using Manex.Authentication.Entities.Identity;

namespace Manex.Authentication.Contracts.Identity
{
    public interface IUsersPhotoService
    {
        string GetUsersAvatarsFolderPath();
        void SetUserDefaultPhoto(User user);
        string GetUserDefaultPhoto(string photoFileName);
        string GetUserPhotoUrl(string photoFileName);
        string GetCurrentUserPhotoUrl();
    }
}