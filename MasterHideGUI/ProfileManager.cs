using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Newtonsoft.Json;

namespace MasterHideGUI
{
    public struct Profile
    {
        public string ProfileName { get; set; }
        public long PolicyFlags { get; set; }
    }

    public static class ProfileManager
    {
        private static string filePath = "profiles.json";
        private static string defaultProfileName = "Default";

        public static void SaveProfiles(List<Profile> profiles)
        {
            string json = JsonConvert.SerializeObject(profiles, Formatting.Indented);
            File.WriteAllText(filePath, json);
        }

        public static List<Profile> LoadProfiles()
        {
            if (File.Exists(filePath))
            {
                string json = File.ReadAllText(filePath);
                return JsonConvert.DeserializeObject<List<Profile>>(json);
            }
            return new List<Profile>();
        }

        public static void EnsureDefaultProfile(List<Profile> profiles)
        {
            bool defaultProfileExists = profiles.Exists(p => p.ProfileName == defaultProfileName);
            if (!defaultProfileExists)
            {
                Profile defaultProfile = new Profile
                {
                    ProfileName = defaultProfileName,
                    PolicyFlags = 0
                };
                profiles.Add(defaultProfile);
                SaveProfiles(profiles);
            }
        }
    }
}
