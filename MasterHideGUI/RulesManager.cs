using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MasterHideGUI
{
    public class ProcessRule
    {
        public string ImageFileName { get; private set; }
        public string ProfileName { get; private set; }

        public ProcessRule(string profileName, string imageFileName)
        {
            ProfileName = profileName;
            ImageFileName = imageFileName;
        }

        public void SetProfileName(string profileName)
        {
            ProfileName = profileName;
        }
    }

    public static class RulesManager
    {
        private static string filePath = "rules.json";

        public static void SaveRules(List<ProcessRule> profiles)
        {
            string json = JsonConvert.SerializeObject(profiles, Formatting.Indented);
            File.WriteAllText(filePath, json);
        }

        public static List<ProcessRule> LoadRules()
        {
            if (File.Exists(filePath))
            {
                string json = File.ReadAllText(filePath);
                return JsonConvert.DeserializeObject<List<ProcessRule>>(json);
            }
            return new List<ProcessRule>();
        }
    }
}
