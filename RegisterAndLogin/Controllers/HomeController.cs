using RegisterAndLogin.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using System.Web.UI.WebControls;
using System.Web.Security;
using System.Data.Entity.Validation;

namespace RegisterAndLogin.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }
        [HttpGet]
        public ActionResult LogIn()
        {
            return View();
        }

        [HttpPost]
        public ActionResult LogIn(Models.UserMaster userr)
        {
            //if (ModelState.IsValid)
            //{
            if (IsValid(userr.Email, userr.Password))
            {
                FormsAuthentication.SetAuthCookie(userr.Email, false);
                return RedirectToAction("Index", "Home");
            }
            else
            {
                ModelState.AddModelError("", "Login details are wrong.");
            }
            return View(userr);
        }
        [HttpGet]
        public ActionResult Register()
        {
            return View();
        }
        [HttpPost]
        public ActionResult Register(Models.UserMaster user)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    using (var db = new RegisterAndLogin.Models.WEB_AJAYEntities())
                    {
                        var crypto = new SimpleCrypto.PBKDF2();
                        var encrypPass = crypto.Compute(user.Password);
                        var newUser = db.UserMasters.Create(); //   .Create();
                        newUser.Email = user.Email;
                        newUser.Password = encrypPass;
                        newUser.PasswordSalt =crypto.Salt;
                        newUser.FirstName = user.FirstName;
                        newUser.LastName = user.LastName;
                        newUser.UserType = "User";
                        newUser.CreatedDate = DateTime.Now;
                        newUser.IsActive = true;
                        newUser.IPAddress = "642 White Hague Avenue";
                        db.UserMasters.Add(newUser);
                        db.SaveChanges();
                        return RedirectToAction("Index", "Home");
                    }
                }
                else
                {
                    ModelState.AddModelError("", "Data is not correct");
                }
            }
            catch (DbEntityValidationException e)
            {
                foreach (var eve in e.EntityValidationErrors)
                {
                    Console.WriteLine("Entity of type \"{0}\" in state \"{1}\" has the following validation errors:",
                        eve.Entry.Entity.GetType().Name, eve.Entry.State);
                    foreach (var ve in eve.ValidationErrors)
                    {
                        Console.WriteLine("- Property: \"{0}\", Error: \"{1}\"",
                            ve.PropertyName, ve.ErrorMessage);
                    }
                }
                throw;
            }
            return View();
        }

        public ActionResult LogOut()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Index", "Home");
        }

        private bool IsValid(string email, string password)
        {
            var crypto = new SimpleCrypto.PBKDF2();
            bool IsValid = false;

            using (var db = new WEB_AJAYEntities())
            {
                var user = db.UserMasters.FirstOrDefault(u => u.Email == email);
                if (user != null)
                {
                    if (user.Password == crypto.Compute(password, user.PasswordSalt))
                    {
                        IsValid = true;
                    }
                }
            }
            return IsValid;
        }
        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
       
    }
}