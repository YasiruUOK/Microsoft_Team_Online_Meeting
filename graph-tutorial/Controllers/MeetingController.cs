using graph_tutorial.Helpers;
using graph_tutorial.Models;
using Microsoft.Graph;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace graph_tutorial.Controllers
{
    public class MeetingController : BaseController
    {
        // GET: Meeting
        [Authorize]
        public async Task<ActionResult> Index()
        {
            var meeting = await GraphHelper.GetMeetingAsync();
            ViewData["JoinURL"] = meeting.JoinUrl;
            return View(meeting);
        }

        public ActionResult NewMeeting()
        {
            return View();
        }


        [Authorize]
        [HttpPost]
        public async Task<ActionResult> CreateMeeting(NewMeetingViewModel model)
        {
            
            //var meeting = await GraphHelper.GetMeetingAsync(model);
            
            return View();
        }
    }
}