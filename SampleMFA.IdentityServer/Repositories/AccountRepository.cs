using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Models;
using SampleMFA.IdentityServer.Models;

namespace SampleMFA.IdentityServer.Repositories
{
    public class AccountRepository : IAccountRepository
    {
        private ApplicationDbContext _db;

        public AccountRepository(ApplicationDbContext context)
        {
            _db = context;
        }

        public Account GetAccount(string username, string password)
        {
            return _db.Accounts.SingleOrDefault(m => m.Username == username && m.EncryptedPassword == password.Sha256());
        }

        public void InsertAccount(string username, string password, string phone, out Guid userGuid)
        {
            userGuid = Guid.NewGuid();
            _db.Accounts.Add(new Account()
            {
                UserGuid = userGuid,
                Username = username,
                EncryptedPassword = password.Sha256(),
                Phone = phone
            });
        }
    }
}
