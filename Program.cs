using DShopAPI.Data;
using DShopAPI.Interfaces;
using DShopAPI.Repository;
using DShopAPI.Services;
using DShopAPI.ViewModels;
using Microsoft.EntityFrameworkCore;
using DShopAPI.Repositories;

namespace DShopAPII
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddControllersWithViews();

            builder.Services.AddScoped<IUserRepository, UserRepository>();
            builder.Services.AddScoped<ICategoryItemRepository, CategoryItemRepository>();
            builder.Services.AddScoped<ICategoryRepository, CategoryRepository>();
            builder.Services.AddScoped<IProductRepository, ProductRepository>();
            builder.Services.AddScoped<IAdminUserRepository, AdminUserRepository>();
            builder.Services.AddScoped<INewsletterSubscriberRepository, NewsletterSubscriberRepository>();
            builder.Services.AddScoped<IWishlistRepository, WishlistRepository>();
            builder.Services.AddScoped<ICartItemRepository, CartItemRepository>();
            builder.Services.AddScoped<IOrderRepository, OrderRepository>();
            builder.Services.AddScoped<IPaymentService, PaymentService>();
            builder.Services.AddScoped<IEmailService, SmtpEmailService>();

            //linking to the DbContext in Mysql
            builder.Services.AddDbContext<DShopDbContext>(options =>
            {
                options.UseSqlServer(builder.Configuration.GetConnectionString("MyString"));
            });

            builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));

            var app = builder.Build();


            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.Run();
        }
    }
}