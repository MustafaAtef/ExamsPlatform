using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace ExamsPlatform.WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        [HttpPost("login")]
        public IActionResult Login()
        {
            return new JsonResult(new
            {
                token = "fake-jwt-token",
                refreshToken = "fake-refresh-token"
            });
        }
    }
}
