using graph_tutorial.TokenStorage;
using Microsoft.Graph;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Web;
using graph_tutorial.Models;
using System;
using System.Net.Http;
using Newtonsoft.Json;
using System.Text;
using Newtonsoft.Json.Linq;
using Microsoft.Graph.Auth;
using System.Net;
using System.IO;

namespace graph_tutorial.Helpers
{
    public static class GraphHelper
    {


        public static async Task<CachedUser> GetUserDetailsAsync(string accessToken)
        {
            var graphClient = new GraphServiceClient(
                new DelegateAuthenticationProvider(
                    async (requestMessage) =>
                    {
                        requestMessage.Headers.Authorization =
                            new AuthenticationHeaderValue("Bearer", accessToken);
                    }));

            var user = await graphClient.Me.Request()
                .Select(u => new
                {
                    u.DisplayName,
                    u.Mail,
                    u.UserPrincipalName
                })
                .GetAsync();

            return new CachedUser
            {
                Avatar = string.Empty,
                DisplayName = user.DisplayName,
                Email = string.IsNullOrEmpty(user.Mail) ?
                    user.UserPrincipalName : user.Mail
            };
        }


        //private static string accessTokenTrial = "";
        // Load configuration settings from PrivateSettings.config
        private static string appId = ConfigurationManager.AppSettings["ida:AppId"];
        private static string appSecret = ConfigurationManager.AppSettings["ida:AppSecret"];
        private static string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];
        private static string graphScopes = ConfigurationManager.AppSettings["ida:AppScopes"];

        public static async Task<IEnumerable<Event>> GetEventsAsync()
        {
            var graphClient = GetAuthenticatedClient();

            //var events = await graphClient.Me.Events.Request()
            //    .Select("subject,organizer,start,end")
            //    .OrderBy("createdDateTime DESC")
            //    .GetAsync();

            var events = await graphClient.Me.Events
    .Request()
    .Header("Prefer", "outlook.timezone=\"Pacific Standard Time\"")
    .Select(e => new {
        e.Subject,
        e.Body,
        e.BodyPreview,
        e.Organizer,
        e.Attendees,
        e.Start,
        e.End,
        e.Location
    })
    .GetAsync();

            return events.CurrentPage;
        }

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
                        requestMessage.Headers.Authorization =
                            new AuthenticationHeaderValue("Bearer", result.AccessToken);
                    }));
        }

        public static async Task<OnlineMeeting> GetMeetingAsync()
        {
            var graphClient = GetAuthenticatedClient();
            //        IConfidentialClientApplication confidentialClientApplication = ConfidentialClientApplicationBuilder
            //.Create(appId)
            //.WithRedirectUri(redirectUri)
            //.WithClientSecret(appSecret) // or .WithCertificate(certificate)
            //.Build();

            //        AuthorizationCodeProvider authProvider = new AuthorizationCodeProvider(confidentialClientApplication, graphScopes.Split(' '));
            //        GraphServiceClient graphClient = new GraphServiceClient(authProvider);

    //        IConfidentialClientApplication confidentialClientApplication = ConfidentialClientApplicationBuilder
    //.Create(appId)
    //.WithTenantId("1dd6ac05-0286-4cb8-987f-cd44134d00d1")
    //.WithClientSecret(appSecret)
    //.Build();

    //        //app secrate 5sRShc9UjqowAJUjkpjg02hha.oTX.].
    //        ClientCredentialProvider authProvider = new ClientCredentialProvider(confidentialClientApplication);
    //        GraphServiceClient graphClient = new GraphServiceClient(authProvider);
            var onlineMeeting = new OnlineMeeting
            {
                StartDateTime = DateTimeOffset.Parse("2019-07-12T21:30:34.2444915+00:00"),
                EndDateTime = DateTimeOffset.Parse("2019-07-12T22:00:34.2464912+00:00"),
                Subject = "User Token Meeting"
            };

            var meeting = await graphClient.Me.OnlineMeetings
                .Request()
                .AddAsync(onlineMeeting);
            return meeting;
        }
    }
}