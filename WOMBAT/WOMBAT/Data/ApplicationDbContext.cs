using WOMBAT.Models;
using WOMBAT.Tools;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace WOMBAT.Data;

public class ApplicationDbContext : IdentityDbContext<User>
{

    private IConfiguration _config;

    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options, IConfiguration config)
        : base(options)
    {
        _config = config;
    }


    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        // Customize the ASP.NET Identity model and override the defaults if needed.
        // For example, you can rename the ASP.NET Identity table names and more.
        // Add your customizations after calling base.OnModelCreating(builder);
    }

    public bool ValidateToken(string token)
    {
        string hashedToken = Convert.ToBase64String(EncodingTools.Hash(token, ""));

        var dbToken = UserTokens.Where(t => t.Value == hashedToken).ToList();

        if (dbToken.Count()<=0) return false;
        return true;

    }



}
