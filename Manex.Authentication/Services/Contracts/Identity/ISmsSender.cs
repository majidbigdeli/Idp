﻿using System.Threading.Tasks;

namespace Manex.Authentication.Contracts.Identity
{
    public interface ISmsSender
    {
        #region BaseClass

        Task SendSmsAsync(string number, string message);

        #endregion

        #region CustomMethods

        #endregion
    }
}