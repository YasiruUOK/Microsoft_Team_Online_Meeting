using System;
using System.Collections.Generic;
using System.Web;
using System.Net;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;
using System.Collections.Specialized;
using System.Configuration;
using Microsoft.Graph;
using System.Net.Http.Headers;
using Microsoft.Identity.Client;
using graph_tutorial.TokenStorage;
using System.Security.Claims;
using System.Linq;
using System.Threading.Tasks;

namespace graph_tutorial.Helpers
{
    public class MeetingHelper
    {
        

        private static string accessTokenTrial = "";
        // Load configuration settings from PrivateSettings.config
        private static string appId = ConfigurationManager.AppSettings["ida:AppId"];
        private static string appSecret = ConfigurationManager.AppSettings["ida:AppSecret"];
        private static string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];
        private static string graphScopes = ConfigurationManager.AppSettings["ida:AppScopes"];

        

        private static GraphServiceClient GetAuthenticatedClient()
        {
            return new GraphServiceClient(
                new DelegateAuthenticationProvider(
                    async (requestMessage) =>
                    {
                        var idClient = ConfidentialClientApplicationBuilder.Create(appId)
                            .WithRedirectUri(redirectUri)
                            .WithClientSecret(appSecret)
                            .Build();

                        var tokenStore = new SessionTokenStore(idClient.UserTokenCache,
                                HttpContext.Current, ClaimsPrincipal.Current);

                        var accounts = await idClient.GetAccountsAsync();

                        // By calling this here, the token can be refreshed
                        // if it's expired right before the Graph call is made
                        var scopes = graphScopes.Split(' ');
                        var result = await idClient.AcquireTokenSilent(scopes, accounts.FirstOrDefault())
                                    .ExecuteAsync();
                        accessTokenTrial = result.AccessToken;
                        requestMessage.Headers.Authorization =
                            new AuthenticationHeaderValue("Bearer", result.AccessToken);
                    }));
        }
        public static async Task<OnlineMeeting> CreateMSTeamsScheduledMeetings()
        {
            var graphClient = GetAuthenticatedClient();
            string GraphURl = "https://graph.microsoft.com/beta/me/onlineMeetings";

                string startDateTime = "2020-07-12T14:30:34";
                string endDateTime = "2020-07-12T15:00:34";
                string subject = "User Token Meeting";

                string PostData = "{\"startDateTime\":\"" + startDateTime + "\",\"endDateTime\":\"" + endDateTime + "\",\"subject\":\"" + subject + "\"}";

                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
                HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(GraphURl);
                webRequest.Method = "POST";
                webRequest.KeepAlive = false;
                webRequest.Accept = "application/json";
                webRequest.ContentType = "application/json";
                //webRequest.Headers.Add(HttpRequestHeader.Authorization, "Bearer " + AccessToken);
                webRequest.Headers.Add(HttpRequestHeader.Authorization, "Bearer " + accessTokenTrial);
                

                ASCIIEncoding encoding = new ASCIIEncoding();
                byte[] byteArray = encoding.GetBytes(PostData);
                webRequest.ContentLength = byteArray.Length;
                Stream dataStream = webRequest.GetRequestStream();
                dataStream.Write(byteArray, 0, byteArray.Length);
                dataStream.Close();

                StreamReader responseReader = new StreamReader(webRequest.GetResponse().GetResponseStream());
                string responseData = responseReader.ReadToEnd();
                return null;

            
        }
    }
}
