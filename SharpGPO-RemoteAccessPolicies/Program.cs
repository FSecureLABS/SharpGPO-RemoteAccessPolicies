using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Text.RegularExpressions;
using System.IO;
using CommandLine;

/*****************************************************************************************************
* author: Dennis Panagiotopoulos -> @den_n1s                                                         *
* Based on prior work by Jon Cave -> @joncave and William Knowles -> @william_knows                  *
* https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/              *
* Checks GPO for settings which deal with remote access policies relevant to lateral movement        *
* (e.g., "EnableLUA" and "LocalAccountTokenFilterPolicy").  The OUs to which these GPOs are applied  *
* are then identified, and then the computer objects from each are retrieved.  Note that this only   *
* retrieves computer objects who have had the relevent registry keys set through group policy.       *
* ****************************************************************************************************/

namespace SharpGPO_RemoteAccessPolicies
{
    class Program
    {
        public static void PrintHelp()
        {
            string HelpText = "\nUsage: SharpGPO-RemoteAccessPolicues.exe <optional options>\n" +
                "\nOptional options:\n" +
                "\n--domain\n" +
                "\tSet the target domain\n" +
                "\n" +
                "\n--domainController\n" +
                "\tSpecifies an Active Directory server (domain controller) to bind to\n" +
                "\n" +
                "\n--searchScope\n" +
                "\tSpecifies the scope to search under, Base/OneLevel/Subtree (default of Subtree)\n" +
                "\n" +
                "\n--searchBase\n" +
                "\tThe LDAP source to search through, e.g. SharpGPO-RemoteAccessPolicies --searchBase /OU=Workstations,DC=domain,DC=local. Useful for OU queries.\n" +
                "\n" +
                "\n--verbose\n" +
                "\tPrint more information about GPOs\n" +
                "\n";
            Console.WriteLine(HelpText);

        }

        public static bool CheckEnableLUA(string GptTmplPath)
        {
            bool enableLUA = false;

            if (File.Exists(GptTmplPath))
            {
                foreach (string line in File.ReadAllLines(GptTmplPath, Encoding.UTF8))
                {
                    string EnableLUAConfiguration = @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,0";
                    if (line.Equals(EnableLUAConfiguration))
                    {
                        enableLUA = true;
                    }
                }
            }
            return enableLUA;
        }

        public static bool CheckFilterAdministratorToken(string GptTmplPath)
        {
            bool FilterAdministratorToken = false;

            if (File.Exists(GptTmplPath))
            {
                foreach (string line in File.ReadAllLines(GptTmplPath, Encoding.UTF8))
                {
                    string FilterAdministratorTokenConfiguration = @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,0";
                    if (line.Equals(FilterAdministratorTokenConfiguration))
                    {
                        FilterAdministratorToken = true;
                    }
                }
            }
            return FilterAdministratorToken;
        }

        public static bool CheckLocalAccountTokenFilterPolicy(string RegistryXMLpath)
        {
            bool LocalAccountTokenFilterPolicy = false;

            if (File.Exists(RegistryXMLpath))
            {
                foreach (string line in File.ReadAllLines(RegistryXMLpath, Encoding.UTF8))
                {
                    string LocalAccountTokenFilterPolicyConfiguration = "name=\"LocalAccountTokenFilterPolicy\" type=\"REG_DWORD\" value=\"00000001\"";
                    if (line.Contains(LocalAccountTokenFilterPolicyConfiguration))
                    {
                        LocalAccountTokenFilterPolicy = true;
                    }
                }
            }
            return LocalAccountTokenFilterPolicy;
        }

        public static bool CheckSeDenyNetworkLogonRight(string GptTmplPath)
        {
            bool SeDenyNetworkLogonRight = false;

            if (File.Exists(GptTmplPath))
            {
                foreach (string line in File.ReadAllLines(GptTmplPath, Encoding.UTF8))
                {
                    string SeDenyNetworkLogonRightConfiguration = @"SeDenyNetworkLogonRight = *S-1-5-32-544";
                    if (line.Contains(SeDenyNetworkLogonRightConfiguration))
                    {
                        SeDenyNetworkLogonRight = true;
                    }
                }
            }

            return SeDenyNetworkLogonRight;
        }

        public static bool CheckSeDenyRemoteInteractiveLogonRight(string GptTmplPath)
        {
            bool SeDenyRemoteInteractiveLogonRight = false;

            if (File.Exists(GptTmplPath))
            {
                foreach (string line in File.ReadAllLines(GptTmplPath, Encoding.UTF8))
                {
                    string SeDenyRemoteInteractiveLogonRightConfiguration = @"SeDenyRemoteInteractiveLogonRight = *S-1-5-32-544";
                    if (line.Contains(SeDenyRemoteInteractiveLogonRightConfiguration))
                    {
                        SeDenyRemoteInteractiveLogonRight = true;
                    }
                }
            }
            return SeDenyRemoteInteractiveLogonRight;
        }

        public class Options
        {
            [Option("", "domain", Required = false, HelpText = "Set the target domain.")]
            public string domain { get; set; }

            [Option("", "searchScope", Required = false, HelpText = "Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).")]
            public string searchScope { get; set; }
            
            [Option("", "domainController", Required = false, HelpText = "Specifies an Active Directory server (domain controller) to bind to.")]
            public string domainController { get; set; }
            
            [Option("", "verbose", Required = false, HelpText = "Print more information about GPOs.")]
            public bool verbose { get; set; }
            
            [Option("", "searchBase", Required = false, HelpText = "The LDAP source to search through, e.g. SharpGPO-RemoteAccessPolicies --searchBase /OU=Workstations,DC=domain,DC=local. Useful for OU queries.")]
            public string searchBase { get; set; }

            [Option("", "help", Required = false, HelpText = "Display help menu.")]
            public bool help { get; set; }


        }

        static void Main(string[] args)
        {
            if (args == null)
            {
                PrintHelp();
                return;
            }

            string domain = "";
            string domainController = "";
            string searchScope = "";
            string searchBase = "";
            bool verbose = false;

            var Options = new Options();

            if (CommandLineParser.Default.ParseArguments(args, Options))
            {
                if (Options.help == true)
                {
                    PrintHelp();
                    return;
                }
                if (!string.IsNullOrEmpty(Options.domain))
                {
                    domain = Options.domain;
                }
                if (string.IsNullOrEmpty(Options.searchScope))
                {
                    searchScope = "SubTree";
                }
                else
                {
                    searchScope = Options.searchScope;
                }
                if (!string.IsNullOrEmpty(Options.domainController))
                {
                    domainController = Options.domainController;
                }
                if (Options.verbose)
                {
                    verbose = true;
                }
                if (!string.IsNullOrEmpty(Options.searchBase))
                {
                    searchBase = Options.searchBase;
                }
            }

            var listEnableLUA = new List<string>();
            var listFilterAdministratorToken = new List<string>();
            var listLocalAccountTokenFilterPolicy = new List<string>();
            var listSeDenyNetworkLogonRight = new List<string>();
            var listSeDenyRemoteInteractiveLogonRight = new List<string>();
            var computerPolicyEnableLUA = new List<string>();
            var computerPolicyFilterAdministratorToken = new List<string>();
            var computerPolicyLocalAccountTokenFilterPolicy = new List<string>();
            var computerPolicySeDenyNetworkLogonRight = new List<string>();
            var computerPolicySeDenyRemoteInteractiveLogonRight = new List<string>();

            //discover current domain            
            System.DirectoryServices.ActiveDirectory.Domain current_domain = null;

            if (string.IsNullOrEmpty(domain))
            {
                try
                {
                    current_domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();
                    domain = current_domain.Name;
                }
                catch
                {
                    Console.WriteLine("[!] Cannot enumerate domain.\n");
                    return;
                }
            }
            else
            {
                DirectoryContext domainContext = new DirectoryContext(DirectoryContextType.Domain, domain);
                try
                {
                    current_domain = System.DirectoryServices.ActiveDirectory.Domain.GetDomain(domainContext);
                }
                catch (Exception)
                {
                    Console.WriteLine("\n[!] The specified domain does not exist or cannot be contacted. Exiting...\n");
                    return;
                }
                
            }
            
            if (string.IsNullOrEmpty(Options.domainController))
            {
                domainController = current_domain.FindDomainController().Name;
            }
            else
            {
                var ldapId = new LdapDirectoryIdentifier(Options.domainController);
                using (var testConnection = new LdapConnection(ldapId))
                {
                    try
                    {
                        testConnection.Bind();
                    }
                    catch
                    {
                        Console.WriteLine("\n[!] The specified domain controller cannot be contacted. Exiting...\n");
                        return;
                    }
                }
            }

            domain = domain.ToLower();        

            String[] DC_array = null;
            String distinguished_name = null;
            distinguished_name = "CN=Policies,CN=System";
            DC_array = domain.Split('.');

            foreach (String DC in DC_array)
            {
                distinguished_name += ",DC=" + DC;
            }
            
            System.DirectoryServices.Protocols.LdapDirectoryIdentifier identifier = new System.DirectoryServices.Protocols.LdapDirectoryIdentifier(domainController, 389);
            System.DirectoryServices.Protocols.LdapConnection connection = null;

            connection = new System.DirectoryServices.Protocols.LdapConnection(identifier);
            connection.SessionOptions.Sealing = true;
            connection.SessionOptions.Signing = true;
            connection.Bind();

            SearchRequest requestGUID = null;
            
            if (string.Equals(searchScope,"SubTree"))
            {
                requestGUID = new System.DirectoryServices.Protocols.SearchRequest(distinguished_name, "cn=*", System.DirectoryServices.Protocols.SearchScope.Subtree, null);
            }
            else if(string.Equals(searchScope, "OneLevel"))
            {
                requestGUID = new System.DirectoryServices.Protocols.SearchRequest(distinguished_name, "cn=*", System.DirectoryServices.Protocols.SearchScope.OneLevel, null);
            }
            else if(string.Equals(searchScope, "Base"))
            {
                requestGUID = new System.DirectoryServices.Protocols.SearchRequest(distinguished_name, "cn=*", System.DirectoryServices.Protocols.SearchScope.Base, null);
            }

            SearchResponse responseGUID = null;
            try
            {
                responseGUID = (System.DirectoryServices.Protocols.SearchResponse)connection.SendRequest(requestGUID);
            }
            catch (Exception)
            {
                Console.WriteLine("\n[!] Search scope is not valid. Exiting...\n");
                return;
            }

            if (!string.IsNullOrEmpty(Options.searchBase))
            {
                string adPath = "LDAP://" + domain + searchBase;
                if (!DirectoryEntry.Exists(adPath))
                {
                    Console.WriteLine("\n[!] Search base {0} is not valid. Exiting...\n", adPath);
                    return;
                }
            }

            Console.WriteLine("\n[-] Domain Controller is: {0}\n[-] Domain is: {1}\n", domainController, domain);

            foreach (System.DirectoryServices.Protocols.SearchResultEntry entry in responseGUID.Entries)
            {
                try
                {
                    var requestAttributes = new System.DirectoryServices.Protocols.SearchRequest(distinguished_name, "cn=" + entry.Attributes["cn"][0].ToString(), System.DirectoryServices.Protocols.SearchScope.OneLevel, null);
                    var responseAttributes = (System.DirectoryServices.Protocols.SearchResponse)connection.SendRequest(requestAttributes);
                    foreach (System.DirectoryServices.Protocols.SearchResultEntry attribute in responseAttributes.Entries)
                    {
                        try
                        {
                            string displayName = entry.Attributes["displayName"][0].ToString();
                            //Console.WriteLine("[+] displayName is: {0}", displayName);
                            string name = entry.Attributes["name"][0].ToString();
                            //Console.WriteLine("[+] name is: {0}", name);
                            string gpcfilesyspath = entry.Attributes["gpcfilesyspath"][0].ToString();
                            //Console.WriteLine("[+] gpcfilesyspath is: {0}\n", gpcfilesyspath);

                            string uncPathGptTmpl = gpcfilesyspath + @"\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf";

                            bool enableLUA = CheckEnableLUA(uncPathGptTmpl);

                            if (enableLUA)
                            {
                                if (verbose)
                                {
                                    Console.WriteLine("[+] The following GPO enables pass-the-hash by disabling EnableLUA: {0} {1}", displayName, name);
                                }
                                listEnableLUA.Add(name);
                            }

                            bool FilterAdministratorToken = CheckFilterAdministratorToken(uncPathGptTmpl);

                            if (FilterAdministratorToken)
                            {
                                if (verbose)
                                {
                                    Console.WriteLine("[+] The following GPO exempts the RID 500 account from UAC protection by disabling FilterAdministratorToken: {0} {1}", displayName, name);
                                }
                                listFilterAdministratorToken.Add(name);
                            }

                            string uncPathRegistryXML = gpcfilesyspath + @"\MACHINE\Preferences\Registry\Registry.xml";

                            bool LocalAccountTokenFilterPolicy = CheckLocalAccountTokenFilterPolicy(uncPathRegistryXML);

                            if (LocalAccountTokenFilterPolicy)
                            {
                                if (verbose)
                                {
                                    Console.WriteLine("[+] The following GPO enables pass-the-hash by enabling LocalAccountTokenFilterPolicy: {0} {1}", displayName, name);
                                }
                                listLocalAccountTokenFilterPolicy.Add(name);
                            }

                            bool SeDenyNetworkLogonRight = CheckSeDenyNetworkLogonRight(uncPathGptTmpl);

                            if (SeDenyNetworkLogonRight)
                            {
                                if (verbose)
                                {
                                    Console.WriteLine("[+] The following GPO includes the built-in Administrators group within the SeDenyNetworkLogonRight: {0} {1}", displayName, name);
                                }
                                listSeDenyNetworkLogonRight.Add(name);
                            }

                            bool SeDenyRemoteInteractiveLogonRight = CheckSeDenyRemoteInteractiveLogonRight(uncPathGptTmpl);

                            if (SeDenyRemoteInteractiveLogonRight)
                            {
                                if (verbose)
                                {
                                    Console.WriteLine("[+] The following GPO includes the built-in Administrators group within the SeDenyRemoteInteractiveLogonRight: {0} {1}\n", displayName, name);
                                }
                                listSeDenyRemoteInteractiveLogonRight.Add(name);
                            }

                        }
                        catch
                        {
                            Console.WriteLine("[!] It was not possible to retrieve the displayname, name and gpcfilesypath...\n");
                            return;
                        }
                    }
                }
                catch
                {
                    Console.WriteLine("[!] It was not possible to retrieve GPO Policies...\n");
                    return;
                }
            }

            Console.Write("\n[+] EnableLUA: \t\t\t\t");
            foreach (var guid in listEnableLUA)
            {
                DirectoryEntry startingPoint = null;
                string filterGPLink = "(&(objectCategory=organizationalUnit)(gplink=*" + guid + "*))";

                if (string.IsNullOrEmpty(searchBase))
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain);
                }
                else
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain + searchBase);
                }

                DirectorySearcher searcher = new DirectorySearcher(startingPoint);
                searcher.Filter = filterGPLink;

                foreach (SearchResult OU in searcher.FindAll())
                {
                    DirectoryEntry startingPoint1 = new DirectoryEntry(OU.Path);
                    DirectorySearcher searcherOU = new DirectorySearcher(startingPoint1);
                    searcherOU.Filter = "(&(samAccountType=805306369))";
                    foreach (SearchResult computerObject in searcherOU.FindAll())
                    {
                        DirectoryEntry computer = computerObject.GetDirectoryEntry();
                        if (!(computerPolicyEnableLUA.Contains(computer.Properties["dNSHostName"].Value.ToString())))
                        {
                            Console.Write("{0} ", computer.Properties["dNSHostName"].Value.ToString());
                        }
                        computerPolicyEnableLUA.Add(computer.Properties["dNSHostName"].Value.ToString());                       
                    }
                }

            }
            //Console.Write("\n");

            Console.Write("\n[+] FilterAdministratorToken: \t\t");
            foreach (var guid in listFilterAdministratorToken)
            {
                DirectoryEntry startingPoint = null;
                string filterGPLink = "(&(objectCategory=organizationalUnit)(gplink=*" + guid + "*))";
                if (string.IsNullOrEmpty(searchBase))
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain);
                }
                else
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain + searchBase);
                }
                
                DirectorySearcher searcher = new DirectorySearcher(startingPoint);
                searcher.Filter = filterGPLink;

                foreach (SearchResult OU in searcher.FindAll())
                {
                    DirectoryEntry startingPoint1 = new DirectoryEntry(OU.Path);
                    DirectorySearcher searcherOU = new DirectorySearcher(startingPoint1);
                    searcherOU.Filter = "(&(samAccountType=805306369))";
                    foreach (SearchResult computerObject in searcherOU.FindAll())
                    {
                        DirectoryEntry computer = computerObject.GetDirectoryEntry();
                        if (!(computerPolicyFilterAdministratorToken.Contains(computer.Properties["dNSHostName"].Value.ToString())))
                        {
                            Console.Write("{0} ", computer.Properties["dNSHostName"].Value.ToString());
                        }
                        computerPolicyFilterAdministratorToken.Add(computer.Properties["dNSHostName"].Value.ToString());
                    }

                }
            }
            Console.Write("\n");

            Console.Write("[+] LocalAccountTokenFilterPolicy: \t");
            foreach (var guid in listLocalAccountTokenFilterPolicy)
            {
                DirectoryEntry startingPoint = null;
                string filterGPLink = "(&(objectCategory=organizationalUnit)(gplink=*" + guid + "*))";
                if (string.IsNullOrEmpty(searchBase))
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain);
                }
                else
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain + searchBase);
                }
                
                DirectorySearcher searcher = new DirectorySearcher(startingPoint);
                searcher.Filter = filterGPLink;

                foreach (SearchResult OU in searcher.FindAll())
                {
                    DirectoryEntry startingPoint1 = new DirectoryEntry(OU.Path);
                    DirectorySearcher searcherOU = new DirectorySearcher(startingPoint1);
                    searcherOU.Filter = "(&(samAccountType=805306369))";
                    foreach (SearchResult computerObject in searcherOU.FindAll())
                    {
                        DirectoryEntry computer = computerObject.GetDirectoryEntry();
                        if (!(computerPolicyLocalAccountTokenFilterPolicy.Contains(computer.Properties["dNSHostName"].Value.ToString())))
                        {
                            Console.Write("{0} ", computer.Properties["dNSHostName"].Value.ToString());
                        }
                        computerPolicyLocalAccountTokenFilterPolicy.Add(computer.Properties["dNSHostName"].Value.ToString());
                    }

                }
            }
            Console.Write("\n");

            Console.Write("[+] SeDenyNetworkLogonRight: \t\t");
            foreach (var guid in listSeDenyNetworkLogonRight)
            {
                DirectoryEntry startingPoint = null;
                string filterGPLink = "(&(objectCategory=organizationalUnit)(gplink=*" + guid + "*))";
                if (string.IsNullOrEmpty(searchBase))
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain);
                }
                else
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain + searchBase);
                }
                
                DirectorySearcher searcher = new DirectorySearcher(startingPoint);
                searcher.Filter = filterGPLink;

                foreach (SearchResult OU in searcher.FindAll())
                {
                    DirectoryEntry startingPoint1 = new DirectoryEntry(OU.Path);
                    DirectorySearcher searcherOU = new DirectorySearcher(startingPoint1);
                    searcherOU.Filter = "(&(samAccountType=805306369))";
                    foreach (SearchResult computerObject in searcherOU.FindAll())
                    {
                        DirectoryEntry computer = computerObject.GetDirectoryEntry();
                        if (!(computerPolicySeDenyNetworkLogonRight.Contains(computer.Properties["dNSHostName"].Value.ToString())))
                        {
                            Console.Write("{0} ", computer.Properties["dNSHostName"].Value.ToString());
                        }
                        computerPolicySeDenyNetworkLogonRight.Add(computer.Properties["dNSHostName"].Value.ToString());
                    }

                }
            }
            Console.Write("\n");

            Console.Write("[+] SeDenyRemoteInteractiveLogonRight: \t");
            foreach (var guid in listSeDenyRemoteInteractiveLogonRight)
            {
                DirectoryEntry startingPoint = null;
                string filterGPLink = "(&(objectCategory=organizationalUnit)(gplink=*" + guid + "*))";
                if (string.IsNullOrEmpty(searchBase))
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain);
                }
                else
                {
                    startingPoint = new DirectoryEntry("LDAP://" + domain + searchBase);
                }
                DirectorySearcher searcher = new DirectorySearcher(startingPoint);
                searcher.Filter = filterGPLink;

                foreach (SearchResult OU in searcher.FindAll())
                {
                    DirectoryEntry startingPoint1 = new DirectoryEntry(OU.Path);
                    DirectorySearcher searcherOU = new DirectorySearcher(startingPoint1);
                    searcherOU.Filter = "(&(samAccountType=805306369))";
                    foreach (SearchResult computerObject in searcherOU.FindAll())
                    {
                        DirectoryEntry computer = computerObject.GetDirectoryEntry();
                        if (!(computerPolicySeDenyRemoteInteractiveLogonRight.Contains(computer.Properties["dNSHostName"].Value.ToString())))
                        {
                            Console.Write("{0} ", computer.Properties["dNSHostName"].Value.ToString());
                        }
                        computerPolicySeDenyRemoteInteractiveLogonRight.Add(computer.Properties["dNSHostName"].Value.ToString());
                    }
                }
            }
            Console.Write("\n");
        }
    }
}
