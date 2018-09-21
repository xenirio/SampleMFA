using Newtonsoft.Json.Linq;
using System.Security.Claims;

namespace SampleMFA.IdentityServer.Authorities
{

    public interface IAuthority
    {
        string[] Payload { get; }
        Claim[] OnVerify(Claim[] claims, JObject payload, string identifier, out bool valid);
        Claim[] OnForward(Claim[] claims);
    }


    public interface IAuthenticator
    {
        Claim[] GetAuthenticationClaims(string identifier);
    }
}
