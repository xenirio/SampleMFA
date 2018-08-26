using SampleMFA.IdentityServer.Models;
using System;

namespace SampleMFA.IdentityServer.Repositories
{
    public interface IAccountRepository
    {
        Account GetAccount(string username, string password);

        void InsertAccount(string username, string password, string phone, out Guid userGuid);
    }
}
