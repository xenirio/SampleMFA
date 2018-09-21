using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using SampleMFA.IdentityServer.Authorities;
using SampleMFA.IdentityServer.Helpers;
using SampleMFA.IdentityServer.Repositories;

namespace SampleMFA.IdentityServer.Controllers
{
    public class AuthorityModel
    {
        public JObject payload { get; set; }
        public string token { get; set; }
    }

    [Produces("application/json")]
    [Route("authority")]
    public class AuthorityController : ControllerBase
    {
        private Dictionary<string, AuthorityIssuer> _issuers;

        public AuthorityController(ILogger<AuthorityController> logger, IAccountRepository authenticationRepository)
        {
            //For testing purpose
            authenticationRepository.InsertAccount("vee", "qwertyui", "+66821113334", out Guid guid);

            _issuers = new Dictionary<string, AuthorityIssuer>()
            {
                {
                    "owner",
                    AuthorityIssuer.Create(new AuthenticationAuthority(), "identity")
                        .Register("account", new AccountAuthority(authenticationRepository))
                        .Register("otp", new OTPAuthority(logger))
                }
            };
        }

        [HttpPost("account")]
        public IActionResult Account([FromBody] AuthorityModel model)
        {
            return Account("", model);
        }

        [HttpPost("account/{authority}")]
        public IActionResult Account(string authority, [FromBody] AuthorityModel model)
        {
            if (model == null || model?.payload == null)
                return Unauthorized();
            var authorities = _issuers["owner"].Authorities;
            if (!authorities.Any())
                return Unauthorized();
            string token = model.token;
            if (string.IsNullOrWhiteSpace(authority))
            {
                authority = authorities.Keys.ToArray()[0];
                token = JwtHelper.GenerateToken(new Claim[] { }, 60);
            }
            if (string.IsNullOrWhiteSpace(token))
                return Unauthorized();

            var principle = JwtHelper.GetClaimsPrincipal(token);
            if (principle?.Identity?.IsAuthenticated == true)
            {
                try
                {
                    var claimsIdentity = principle.Identity as ClaimsIdentity;
                    var verifyResult = _issuers["owner"].Verify(authority, claimsIdentity.Claims.ToArray(), model.payload);
                    if (verifyResult.Authority == null)
                        return Ok(new { auth_token = verifyResult.Token });
                    return Ok(new { verify_token = verifyResult.Token, authority = verifyResult.Authority, parameters = verifyResult.Payload });
                }
                catch
                {
                    return Unauthorized();
                }
            }
            return Unauthorized();
        }
    }
}