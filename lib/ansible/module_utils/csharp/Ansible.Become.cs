using Microsoft.Win32.SafeHandles;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Ansible.AccessToken;
using Ansible.Lsa;
using Ansible.Process;

namespace Ansible.Become
{
    internal class NativeMethods
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(
            SafeNativeHandle hToken,
            LogonFlags dwLogonFlags,
            [MarshalAs(UnmanagedType.LPWStr)] string lpApplicationName,
            StringBuilder lpCommandLine,
            Process.NativeHelpers.ProcessCreationFlags dwCreationFlags,
            Process.SafeMemoryBuffer lpEnvironment,
            [MarshalAs(UnmanagedType.LPWStr)] string lpCurrentDirectory,
            Process.NativeHelpers.STARTUPINFOEX lpStartupInfo,
            out Process.NativeHelpers.PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        public static extern UInt32 GetCurrentThreadId();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern NoopSafeHandle GetProcessWindowStation();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern NoopSafeHandle GetThreadDesktop(
            UInt32 dwThreadId);
    }

    internal class NoopSafeHandle : SafeHandle
    {
        public NoopSafeHandle() : base(IntPtr.Zero, false) { }
        public override bool IsInvalid { get { return false; } }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle() { return true; }
    }

    [Flags]
    public enum LogonFlags
    {
        WithProfile = 0x00000001,
        NetcredentialsOnly = 0x00000002
    }

    public class BecomeUtil
    {
        private static SecurityIdentifier SYSTEM_SID = new SecurityIdentifier("S-1-5-18");
        private static SecurityIdentifier LOCAL_SERVICE_SID = new SecurityIdentifier("S-1-5-19");
        private static SecurityIdentifier NETWORK_SERVICE_SID = new SecurityIdentifier("S-1-5-20");
        private static string SERVICE_SID_PREFIX = "S-1-5-80-";

        private static List<SecurityIdentifier> SERVICE_SIDS = new List<SecurityIdentifier>()
        {
            SYSTEM_SID,
            LOCAL_SERVICE_SID,
            NETWORK_SERVICE_SID,
        };

        private static int WINDOWS_STATION_ALL_ACCESS = 0x000F037F;
        private static int DESKTOP_RIGHTS_ALL_ACCESS = 0x000F01FF;

        public static Result CreateProcessAsUser(string username, string password, string command)
        {
            return CreateProcessAsUser(username, password, LogonFlags.WithProfile, LogonType.Interactive,
                 null, command, null, null, "");
        }

        public static Result CreateProcessAsUser(string username, string password, LogonFlags logonFlags, LogonType logonType,
            string lpApplicationName, string lpCommandLine, string lpCurrentDirectory, IDictionary environment,
            string stdin)
        {
            byte[] stdinBytes;
            if (String.IsNullOrEmpty(stdin))
                stdinBytes = new byte[0];
            else
            {
                if (!stdin.EndsWith(Environment.NewLine))
                    stdin += Environment.NewLine;
                stdinBytes = new UTF8Encoding(false).GetBytes(stdin);
            }
            return CreateProcessAsUser(username, password, logonFlags, logonType, lpApplicationName, lpCommandLine,
                lpCurrentDirectory, environment, stdinBytes);
        }

        /// <summary>
        /// Creates a process as another user account. This method will attempt to run as another user with the
        /// highest possible permissions available. The main privilege required is the SeDebugPrivilege, without
        /// this privilege you can only run as a local or domain user if the username and password is specified.
        /// </summary>
        /// <param name="username">The username of the runas user</param>
        /// <param name="password">The password of the runas user</param>
        /// <param name="logonFlags">LogonFlags to control how to logon a user when the password is specified</param>
        /// <param name="logonType">Controls what type of logon is used, this only applies when the password is specified</param>
        /// <param name="lpApplicationName">The name of the executable or batch file to executable</param>
        /// <param name="lpCommandLine">The command line to execute, typically this includes lpApplication as the first argument</param>
        /// <param name="lpCurrentDirectory">The full path to the current directory for the process, null will have the same cwd as the calling process</param>
        /// <param name="environment">A dictionary of key/value pairs to define the new process environment</param>
        /// <param name="stdin">Bytes sent to the stdin pipe</param>
        /// <returns>Ansible.Process.Result object that contains the command output and return code</returns>
        public static Result CreateProcessAsUser(string username, string password, LogonFlags logonFlags, LogonType logonType,
            string lpApplicationName, string lpCommandLine, string lpCurrentDirectory, IDictionary environment, byte[] stdin)
        {
            // While we use STARTUPINFOEX having EXTENDED_STARTUPINFO_PRESENT causes a parameter validation error
            Process.NativeHelpers.ProcessCreationFlags creationFlags = Process.NativeHelpers.ProcessCreationFlags.CREATE_UNICODE_ENVIRONMENT;
            Process.NativeHelpers.PROCESS_INFORMATION pi = new Process.NativeHelpers.PROCESS_INFORMATION();
            Process.NativeHelpers.STARTUPINFOEX si = new Process.NativeHelpers.STARTUPINFOEX();
            si.startupInfo.dwFlags = Process.NativeHelpers.StartupInfoFlags.USESTDHANDLES;

            SafeFileHandle stdoutRead, stdoutWrite, stderrRead, stderrWrite, stdinRead, stdinWrite;
            ProcessUtil.CreateStdioPipes(si, out stdoutRead, out stdoutWrite, out stderrRead, out stderrWrite,
                out stdinRead, out stdinWrite);
            FileStream stdinStream = new FileStream(stdinWrite, FileAccess.Write);

            // $null from PowerShell ends up as an empty string, we need to convert back as an empty string doesn't
            // make sense for these parameters
            if (lpApplicationName == "")
                lpApplicationName = null;

            if (lpCurrentDirectory == "")
                lpCurrentDirectory = null;

            // A user may have 2 tokens, 1 limited and 1 elevated. GetUserTokens will return both token to ensure
            // we don't close one of the pairs while the process is still running. If the process tries to retrieve
            // one of the pairs and the token handle is closed then it will fail with ERROR_NO_SUCH_LOGON_SESSION.
            List<SafeNativeHandle> userTokens = GetUserTokens(username, password, logonType);
            try
            {
                using (Process.SafeMemoryBuffer lpEnvironment = ProcessUtil.CreateEnvironmentPointer(environment))
                {
                    bool launchSuccess = false;
                    StringBuilder commandLine = new StringBuilder(lpCommandLine);
                    foreach (SafeNativeHandle token in userTokens)
                    {
                        // GetUserTokens could return null if an elevated token could not be retrieved.
                        if (token == null)
                            continue;

                        if (NativeMethods.CreateProcessWithTokenW(token, logonFlags, lpApplicationName,
                                commandLine, creationFlags, lpEnvironment, lpCurrentDirectory, si, out pi))
                        {
                            launchSuccess = true;
                            break;
                        }
                    }

                    if (!launchSuccess)
                        throw new Process.Win32Exception("CreateProcessWithTokenW() failed");
                }
                return ProcessUtil.WaitProcess(stdoutRead, stdoutWrite, stderrRead, stderrWrite, stdinStream, stdin,
                    pi.hProcess);
            }
            finally
            {
                userTokens.Where(t => t != null).ToList().ForEach(t => t.Dispose());
            }
        }

        private static List<SafeNativeHandle> GetUserTokens(string username, string password, LogonType logonType)
        {
            List<SafeNativeHandle> userTokens = new List<SafeNativeHandle>();

            bool impersonated = false;
            SecurityIdentifier becomeSid = null;
            List<GroupInfo> extraGroups = new List<GroupInfo>();
            SafeNativeHandle systemToken = null;
            if (logonType != LogonType.NewCredentials)
            {
                // Try and impersonate a SYSTEM token, we need a SYSTEM token to either become a well known service
                // account or have administrative rights on the become access token.
                //using (SafeNativeHandle systemToken = GetPrimaryTokenForUser(SYSTEM_SID,
                //    new List<string>() { "SeTcbPrivilege" }))
                systemToken = GetPrimaryTokenForUser(SYSTEM_SID, new List<string>() { "SeTcbPrivilege" });
                if (systemToken != null)
                {
                    if (systemToken != null)
                    {
                        try
                        {
                            TokenUtil.ImpersonateToken(systemToken);
                            impersonated = true;
                        }
                        catch (Process.Win32Exception) { }  // We tried, just rely on current user's permissions.
                    }
                }

                // If prefixed with .\, we are becoming a local account, strip the prefix then finally normalise the
                // account nae.
                if (username.StartsWith(".\\"))
                    username = username.Substring(2);

                becomeSid = (SecurityIdentifier)new NTAccount(username).Translate(typeof(SecurityIdentifier));

                if (becomeSid.Value.StartsWith(SERVICE_SID_PREFIX))
                {
                    // Seems like LsaLogonUser fails when the first group is an NT SERVICE group, instead we will add
                    // 2 groups with the first one being the target become user with SE_GROUP_OWNER which does not add
                    // any more privileges than what they would have had before.
                    extraGroups.Add(new GroupInfo()
                    {
                        Sid = SYSTEM_SID,
                        Attributes = GroupAttributes.Owner,
                    });
                    extraGroups.Add(new GroupInfo() {
                        Sid = becomeSid,
                        Attributes = GroupAttributes.Enabled | GroupAttributes.EnabledByDefault |
                            GroupAttributes.Owner,
                    });

                    // TODO: Use the actual service account name.
                    becomeSid = SYSTEM_SID;
                }
                username = becomeSid.Translate(typeof(NTAccount)).Value;

                // Grant access to the current Windows Station and Desktop to the become user
                GrantAccessToWindowStationAndDesktop(becomeSid);
            }

            string domain = "";
            if (username.Contains(@"\"))
            {
                string[] userSplit = username.Split(new char[] { '\\' }, 2);
                domain = userSplit[0];
                username = userSplit[1];
            }

            // We require impersonation if becoming a service sid or becoming a user without a password
            if (!impersonated && (SERVICE_SIDS.Contains(becomeSid) || String.IsNullOrEmpty(password) || extraGroups.Count > 0))
                throw new Exception("Failed to get token for NT AUTHORITY\\SYSTEM required for become as a service account or an account without a password");

            try
            {
                // Cannot use String.IsEmptyOrNull() as an empty string is an account that doesn't have a pass.
                // We only use S4U if no password was defined or it was null
                if (!SERVICE_SIDS.Contains(becomeSid) && password == null && logonType != LogonType.NewCredentials)
                {
                    // If no password was specified, try and duplicate an existing token for that user or use S4U to
                    // generate one without network credentials
                    SafeNativeHandle becomeToken = GetPrimaryTokenForUser(becomeSid);
                    if (becomeToken != null)
                    {
                        userTokens.Add(GetElevatedToken(becomeToken));
                        userTokens.Add(becomeToken);
                    }
                    else
                    {
                        // S4U only supports a Batch or Network logon, fallback to Batch unless Network was
                        // explicitly set.
                        if (logonType != LogonType.Network)
                            logonType = LogonType.Batch;

                        becomeToken = LsaUtil.LogonUserS4U(username, domain, logonType, extraGroups);
                        userTokens.Add(becomeToken);
                    }
                }
                else
                {
                    if (SERVICE_SIDS.Contains(becomeSid))
                    {
                        logonType = LogonType.Service;
                        password = "";
                    }

                    SafeNativeHandle hToken = LsaUtil.LogonUserInteractive(username, domain, password, logonType,
                        extraGroups);

                    // Get the elevated token for a local/domain accounts only
                    if (!SERVICE_SIDS.Contains(becomeSid))
                        userTokens.Add(GetElevatedToken(hToken));
                    userTokens.Add(hToken);
                }
            }
            finally
            {
                if (impersonated)
                    TokenUtil.RevertToSelf();
            }

            return userTokens;
        }

        private static SafeNativeHandle GetPrimaryTokenForUser(SecurityIdentifier sid, List<string> requiredPrivileges = null)
        {
            // According to CreateProcessWithTokenW we require a token with
            //  TOKEN_QUERY, TOKEN_DUPLICATE and TOKEN_ASSIGN_PRIMARY
            // Also add in TOKEN_IMPERSONATE so we can get an impersonated token
            TokenAccessLevels dwAccess = TokenAccessLevels.Query |
                TokenAccessLevels.Duplicate |
                TokenAccessLevels.AssignPrimary |
                TokenAccessLevels.Impersonate;

            foreach (SafeNativeHandle hToken in TokenUtil.EnumerateUserTokens(sid, dwAccess))
            {
                // Filter out any Network logon tokens, using become with that is useless when S4U
                // can give us a Batch logon
                TokenStatistics stats = TokenUtil.GetTokenStatistics(hToken);
                try
                {
                    LogonType tokenLogonType = LsaUtil.GetLogonSessionData(stats.AuthenticationId).LogonType;
                    if (tokenLogonType == LogonType.Network)
                        continue;
                }
                catch (LsaException)
                {
                    continue;
                }

                // Check that the required privileges are on the token
                if (requiredPrivileges != null)
                {
                    List<string> actualPrivileges = TokenUtil.GetTokenPrivileges(hToken).Select(x => x.Name).ToList();
                    int missing = requiredPrivileges.Where(x => !actualPrivileges.Contains(x)).Count();
                    if (missing > 0)
                        continue;
                }

                // Duplicate the token to convert it to a primary token with the access level required.
                try
                {
                    return TokenUtil.DuplicateToken(hToken, TokenAccessLevels.MaximumAllowed, SecurityImpersonationLevel.Anonymous,
                        TokenType.Primary);
                }
                catch (Process.Win32Exception)
                {
                    continue;
                }
            }

            return null;
        }

        private static SafeNativeHandle GetElevatedToken(SafeNativeHandle hToken)
        {
            TokenElevationType tet = TokenUtil.GetTokenElevationType(hToken);
            // We already have the best token we can get, no linked token is really available.
            if (tet != TokenElevationType.Limited)
                return null;

            SafeNativeHandle linkedToken = TokenUtil.GetTokenLinkedToken(hToken);
            TokenStatistics tokenStats = TokenUtil.GetTokenStatistics(linkedToken);

            // We can only use a token if it's a primary one (we had the SeTcbPrivilege set)
            if (tokenStats.TokenType == TokenType.Primary)
                return linkedToken;
            else
                return null;
        }

        private static void GrantAccessToWindowStationAndDesktop(IdentityReference account)
        {
            GrantAccess(account, NativeMethods.GetProcessWindowStation(), WINDOWS_STATION_ALL_ACCESS);
            GrantAccess(account, NativeMethods.GetThreadDesktop(NativeMethods.GetCurrentThreadId()), DESKTOP_RIGHTS_ALL_ACCESS);
        }

        private static void GrantAccess(IdentityReference account, NoopSafeHandle handle, int accessMask)
        {
            GenericSecurity security = new GenericSecurity(false, ResourceType.WindowObject, handle, AccessControlSections.Access);
            security.AddAccessRule(new GenericAccessRule(account, accessMask, AccessControlType.Allow));
            security.Persist(handle, AccessControlSections.Access);
        }

        private class GenericSecurity : NativeObjectSecurity
        {
            public GenericSecurity(bool isContainer, ResourceType resType, SafeHandle objectHandle, AccessControlSections sectionsRequested)
                : base(isContainer, resType, objectHandle, sectionsRequested) { }
            public new void Persist(SafeHandle handle, AccessControlSections includeSections) { base.Persist(handle, includeSections); }
            public new void AddAccessRule(AccessRule rule) { base.AddAccessRule(rule); }
            public override Type AccessRightType { get { throw new NotImplementedException(); } }
            public override AccessRule AccessRuleFactory(System.Security.Principal.IdentityReference identityReference, int accessMask, bool isInherited,
                InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type)
            { throw new NotImplementedException(); }
            public override Type AccessRuleType { get { return typeof(AccessRule); } }
            public override AuditRule AuditRuleFactory(System.Security.Principal.IdentityReference identityReference, int accessMask, bool isInherited,
                InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AuditFlags flags)
            { throw new NotImplementedException(); }
            public override Type AuditRuleType { get { return typeof(AuditRule); } }
        }

        private class GenericAccessRule : AccessRule
        {
            public GenericAccessRule(IdentityReference identity, int accessMask, AccessControlType type) :
                base(identity, accessMask, false, InheritanceFlags.None, PropagationFlags.None, type)
            { }
        }
    }
}
