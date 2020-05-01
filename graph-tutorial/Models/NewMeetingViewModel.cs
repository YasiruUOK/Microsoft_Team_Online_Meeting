using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace graph_tutorial.Models
{
    public class NewMeetingViewModel
    {
        public string Subject { get; set; }

        public DateTime Start { get; set; }

        public DateTime End { get; set; }

        
        

        internal IEnumerable<string> Attendees { get; set; }

        public string TeamId { get; set; }

        public string ChannelId { get; set; }

        public string JoinURL { get; set; }
    }
}