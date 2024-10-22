using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Reflection.Emit;
using UserAuthenticationApp.Models;

namespace UserAuthentication.Models
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {

        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            //seedRoles(builder);
            //addAdmin(builder);
            builder.Entity<IdentityUserRole<string>>().HasData(
                new IdentityUserRole<string>
                {
                    UserId = "65fe8fe3-9e08-418b-9d15-a7fa2853b2a5", // Admin user ID
                    RoleId = "cdeb4fb0-2c1a-45d8-b768-bd517baf4d95"  // Admin role ID
                }
            );
        }

        private static void seedRoles(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<IdentityRole>().HasData(
                new IdentityRole() { Name = "Admin", ConcurrencyStamp = "1", NormalizedName = "Admin".ToUpper() },
                new IdentityRole() { Name = "User", ConcurrencyStamp = "2", NormalizedName = "User".ToUpper() }
                );
        }

        private static void addAdmin(ModelBuilder modelBuilder)
        {
            var adminUser = new ApplicationUser()
            {
                FirstName = "Omar",
                LastName = "Salah",
                UserName = "omar_salah",
                Email = "omarsalah@test.com",
                EmailConfirmed = true,
                NormalizedUserName = "OMAR_SALAH",
                NormalizedEmail = "omarsalah@test.com".ToUpper(),

            };
            var passwordHasher = new PasswordHasher<ApplicationUser>();
            adminUser.PasswordHash = passwordHasher.HashPassword(adminUser, "P@ssw0rd");
            modelBuilder.Entity<ApplicationUser>().HasData(adminUser);

        }
    }
}
