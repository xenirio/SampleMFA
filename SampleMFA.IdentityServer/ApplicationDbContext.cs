using Microsoft.EntityFrameworkCore;
using SampleMFA.IdentityServer.Models;

namespace SampleMFA.IdentityServer
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext() { }
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }
        public virtual DbSet<Account> Accounts { get; set; }
    }
}
