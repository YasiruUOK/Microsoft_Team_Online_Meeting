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
        //public string MSTeamsAuthCode = "";
        //public string ClientId = "ea4e0501-13b5-4f81-86b4-eea448e337cd";
        //public string ClientSecret = "YONp-SwAvLX1PDbkLcSOj=WuCN0N8/@3";
        //public string TenantId = "ed5c15b1-b176-441a-8e2d-3d115d4b0b63";
        //public string RedirectUrl = "https://staging-v6.netexam.com/ws/MicrosoftTeams.aspx";
        //public string AccessToken = "";
        //public string RefreshToken = "";

        //MeetingHelper()
        //{
        //    //MSTeamsAuthCode = (Request.QueryString["code"]);
        //    GetAccessTokenMSTeams(MSTeamsAuthCode);
        //    //CreateMSTeams();
        //    //UpdateMSTeams();
        //    //CreateMSTeamsScheduledMeetings();

        //}


        //#region GetAuthorizationCodeMSTeams
        //public string GetAuthorizationCodeMSTeams()
        //{
        //    try
        //    {
        //        string AuthCodeUrl = "https://login.microsoftonline.com/" + TenantId + "/oauth2/v2.0/authorize?client_id=" + ClientId + "&response_type=code&redirect_uri=" + RedirectUrl + "&response_mode=query&scope=offline_access%20user.read%20mail.read&state=12345";
        //        HttpContext.Current.Response.Redirect(AuthCodeUrl, false);
        //    }

        //    catch (Exception ex)
        //    {
        //        Logger.Error
        //            (ex, System.Reflection.MethodBase.GetCurrentMethod());
        //        throw;
        //    }

        //    return null;

        //}

        //#endregion


        //#region GetAccessTokenMSTeams
        //public void GetAccessTokenMSTeams(string MSTeamsAuthCode)
        //{
        //    try
        //    {
        //        string getAccessTokenUrl = "https://login.microsoftonline.com/" + TenantId + "/oauth2/v2.0/token";
        //        //string getAccessTokenUrl = "https://login.microsoftonline.com/" + TenantId + "/oauth2/token";
        //        string PostData = "client_id=" + ClientId + "&scope=user.read%20mail.read&code=" + MSTeamsAuthCode + "&redirect_uri=" + RedirectUrl + "&grant_type=authorization_code&client_secret=" + ClientSecret;

        //        ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
        //        HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(getAccessTokenUrl);
        //        webRequest.Method = "POST";
        //        webRequest.KeepAlive = false;
        //        webRequest.Accept = "application/json";
        //        webRequest.ContentType = "application/x-www-form-urlencoded";
        //        webRequest.Headers.Add(HttpRequestHeader.Authorization, "Basic ");
        //        webRequest.ContentLength = 0;
        //        //webRequest.Host = "login.microsoftonline.com";

        //        ASCIIEncoding encoding = new ASCIIEncoding();
        //        byte[] byteArray = encoding.GetBytes(PostData);
        //        webRequest.ContentLength = byteArray.Length;
        //        Stream dataStream = webRequest.GetRequestStream();
        //        dataStream.Write(byteArray, 0, byteArray.Length);
        //        dataStream.Close();

        //        StreamReader responseReader = null;
        //        string responseData = "";
        //        responseReader = new StreamReader(webRequest.GetResponse().GetResponseStream());
        //        responseData = responseReader.ReadToEnd();

        //        var jss = new JavaScriptSerializer();
        //        var dict = jss.Deserialize<Dictionary<string, string>>(responseData);

        //        NameValueCollection nvc = null;
        //        if (dict != null)
        //        {
        //            nvc = new NameValueCollection(dict.Count);
        //            foreach (var k in dict)
        //            {
        //                nvc.Add(k.Key, k.Value);
        //            }
        //        }

        //        AccessToken = nvc["access_token"].ToString();
        //        RefreshToken = nvc["refresh_token"].ToString();

        //    }

        //    catch (Exception ex)
        //    {
        //        Logger.Error
        //            (ex, System.Reflection.MethodBase.GetCurrentMethod());
        //        throw;
        //    }

        //}

        //#endregion


        //#region GetNewAccessTokenUsingRefreshToken
        //public void GetNewAccessTokenUsingRefreshToken(string AccessToken)
        //{
        //    try
        //    {
        //        string getAccessTokenUrl1 = "https://login.microsoftonline.com/" + TenantId + "/oauth2/v2.0/token";
        //        string PostData1 = "client_id=" + ClientId + "&scope=user.read%20mail.read&refresh_token=" + AccessToken + "&redirect_uri=" + RedirectUrl + "&grant_type=refresh_token&client_secret=" + ClientSecret;

        //        ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
        //        HttpWebRequest webRequest1 = (HttpWebRequest)WebRequest.Create(getAccessTokenUrl1);
        //        webRequest1.Method = "POST";
        //        webRequest1.KeepAlive = false;
        //        webRequest1.Accept = "application/json";
        //        webRequest1.ContentType = "application/x-www-form-urlencoded";
        //        webRequest1.Headers.Add(HttpRequestHeader.Authorization, "Basic ");
        //        webRequest1.ContentLength = 0;
        //        //webRequest.Host = "login.microsoftonline.com";

        //        ASCIIEncoding encoding = new ASCIIEncoding();
        //        byte[] byteArray = encoding.GetBytes(PostData1);
        //        webRequest1.ContentLength = byteArray.Length;
        //        Stream dataStream = webRequest1.GetRequestStream();
        //        dataStream.Write(byteArray, 0, byteArray.Length);
        //        dataStream.Close();

        //        StreamReader responseReader = null;
        //        string responseData = "";
        //        responseReader = new StreamReader(webRequest1.GetResponse().GetResponseStream());
        //        responseData = responseReader.ReadToEnd();

        //        var jss = new JavaScriptSerializer();
        //        var dict = jss.Deserialize<Dictionary<string, string>>(responseData);

        //        NameValueCollection nvc = null;
        //        if (dict != null)
        //        {
        //            nvc = new NameValueCollection(dict.Count);
        //            foreach (var k in dict)
        //            {
        //                nvc.Add(k.Key, k.Value);
        //            }
        //        }

        //        AccessToken = nvc["access_token"].ToString();
        //        RefreshToken = nvc["refresh_token"].ToString();

        //    }

        //    catch (Exception ex)
        //    {

        //    }
        //}

        //#endregion



        //#region CreateMSTeams
        //public void CreateMSTeams()
        //{
        //    try
        //    {
        //        string GraphURl = "https://graph.microsoft.com/beta/teams";

        //        string TemplateBind = "https://graph.microsoft.com/beta/teamsTemplates('educationClass')";
        //        string DisplayName = "Team 1 - Education Class";
        //        string Description = "Description of Team 1";

        //        string PostData = "{\"template@odata.bind\":\"" + TemplateBind + "\",\"displayName\":\"" + DisplayName + "\",\"description\":\"" + Description + "\"}";

        //        ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
        //        HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(GraphURl);
        //        webRequest.Method = "POST";
        //        webRequest.KeepAlive = false;
        //        webRequest.Accept = "application/json";
        //        webRequest.ContentType = "application/json";
        //        webRequest.Headers.Add(HttpRequestHeader.Authorization, "Bearer " + AccessToken);
        //        webRequest.ContentLength = 244;

        //        ASCIIEncoding encoding = new ASCIIEncoding();
        //        byte[] byteArray = encoding.GetBytes(PostData);
        //        webRequest.ContentLength = byteArray.Length;
        //        Stream dataStream = webRequest.GetRequestStream();
        //        dataStream.Write(byteArray, 0, byteArray.Length);
        //        dataStream.Close();

        //        HttpWebResponse response = (HttpWebResponse)webRequest.GetResponse();
        //        string Response1 = response.GetResponseHeader("Location");

        //        string GraphURl1 = "https://graph.microsoft.com/beta" + Response1;

        //        ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
        //        HttpWebRequest webRequest1 = (HttpWebRequest)WebRequest.Create(GraphURl1);
        //        webRequest1.Method = "GET";
        //        webRequest1.KeepAlive = false;
        //        webRequest1.Accept = "application/json";
        //        webRequest1.ContentType = "application/json";
        //        webRequest1.Headers.Add(HttpRequestHeader.Authorization, "Bearer " + AccessToken);

        //        StreamReader responseReader = new StreamReader(webRequest1.GetResponse().GetResponseStream());
        //        string responseData = responseReader.ReadToEnd();

        //    }

        //    catch (Exception ex)
        //    {

        //    }
        //}


        //#endregion


        //#region UpdateMSTeams
        //public void UpdateMSTeams()
        //{
        //    try
        //    {
        //        string GraphURl = "https://graph.microsoft.com/beta/teams/3f1c7137-dbc1-48ca-a5bf-ac8177b9a1e5";

        //        string TemplateBind = "https://graph.microsoft.com/beta/teamsTemplates('educationClass')";
        //        string DisplayName = "Team 1 Update - Public";
        //        string Description = "Description of Team 1";

        //        string PostData = "{\"template@odata.bind\":\"" + TemplateBind + "\",\"displayName\":\"" + DisplayName + "\",\"description\":\"" + Description + "\"}";

        //        ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
        //        HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(GraphURl);
        //        webRequest.Method = "PATCH";
        //        webRequest.KeepAlive = false;
        //        webRequest.Accept = "application/json";
        //        webRequest.ContentType = "application/json";
        //        webRequest.Headers.Add(HttpRequestHeader.Authorization, "Bearer " + AccessToken);
        //        webRequest.ContentLength = 211;

        //        ASCIIEncoding encoding = new ASCIIEncoding();
        //        byte[] byteArray = encoding.GetBytes(PostData);
        //        webRequest.ContentLength = byteArray.Length;
        //        Stream dataStream = webRequest.GetRequestStream();
        //        dataStream.Write(byteArray, 0, byteArray.Length);
        //        dataStream.Close();

        //        StreamReader responseReader = new StreamReader(webRequest.GetResponse().GetResponseStream());
        //        string responseData = responseReader.ReadToEnd();

        //    }

        //    catch (Exception ex)
        //    {

        //    }
        //}


        //#endregion


        //#region CreateMSTeamsScheduledMeetings

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