using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Ansible.AccessToken;

namespace Ansible.Lsa
{
    internal class NativeHelpers
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_INTERACTIVE_LOGON
        {
            public UInt32 MessageType;
            public LSA_UNICODE_STRING LogonDomainName;
            public LSA_UNICODE_STRING UserName;
            public LSA_UNICODE_STRING Password;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_S4U_LOGON
        {
            public UInt32 MessageType;
            public UInt32 Flags;
            public LSA_UNICODE_STRING ClientUpn;
            public LSA_UNICODE_STRING ClientRealm;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_LAST_INTER_LOGON_INFO
        {
            public Int64 LastSuccessfulLogon;
            public Int64 LastFailedLogon;
            public UInt32 FailedAttemptCountSinceLastSuccessfulLogon;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct LSA_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            [MarshalAs(UnmanagedType.LPStr)] public string Buffer;

            public static implicit operator string(LSA_STRING s)
            {
                return s.Buffer;
            }

            public static implicit operator LSA_STRING(string s)
            {
                if (s == null)
                    s = "";

                LSA_STRING lsaStr = new LSA_STRING
                {
                    Buffer = s,
                    Length = (UInt16)s.Length,
                    MaximumLength = (UInt16)(s.Length + 1),
                };
                return lsaStr;
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LSA_UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;

            public static LSA_UNICODE_STRING FromString(string s, IntPtr buffer)
            {
                byte[] sBytes = Encoding.Unicode.GetBytes(s);
                Marshal.Copy(sBytes, 0, buffer, sBytes.Length);
                return new LSA_UNICODE_STRING()
                {
                    Length = (UInt16)sBytes.Length,
                    MaximumLength = (UInt16)sBytes.Length,
                    Buffer = buffer,
                };
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(Buffer, Length);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_LOGON_SESSION_DATA
        {
            public UInt32 Size;
            public Luid LogonId;
            public LSA_UNICODE_STRING UserName;
            public LSA_UNICODE_STRING LogonDomain;
            public LSA_UNICODE_STRING AuthenticationPackage;
            public LogonType LogonType;
            public UInt32 Session;
            public IntPtr Sid;
            public Int64 LogonTime;
            public LSA_UNICODE_STRING LogonServer;
            public LSA_UNICODE_STRING DnsDomainName;
            public LSA_UNICODE_STRING Upn;
            public UInt32 UserFlags;
            public LSA_LAST_INTER_LOGON_INFO LastLogonInfo;
            public LSA_UNICODE_STRING LogonScript;
            public LSA_UNICODE_STRING ProfilePath;
            public LSA_UNICODE_STRING HomeDirectory;
            public LSA_UNICODE_STRING HomeDirectoryDrive;
            public Int64 LogoffTime;
            public Int64 KickOffTime;
            public Int64 PasswordLastSet;
            public Int64 PasswordCanChange;
            public Int64 PasswordMustChange;
        }
    }

    internal class NativeMethods
    {
        [DllImport("Advapi32.dll", SetLastError = true)]
        public static extern bool AllocateLocallyUniqueId(
            out Luid Luid);

        [DllImport("Secur32.dll")]
        public static extern UInt32 LsaConnectUntrusted(
            out SafeLsaLogon LsaHandle);

        [DllImport("Secur32.dll")]
        public static extern UInt32 LsaDeregisterLogonProcess(
            IntPtr LsaHandle);

        [DllImport("Secur32.dll")]
        public static extern UInt32 LsaFreeReturnBuffer(
            IntPtr Buffer);

        [DllImport("Secur32.dll")]
        public static extern UInt32 LsaGetLogonSessionData(
            ref Luid LogonId,
            out SafeLsaMemoryBuffer ppLogonSessionData);

        [DllImport("Secur32.dll")]
        public static extern UInt32 LsaLogonUser(
            SafeLsaLogon LsaHandle,
            NativeHelpers.LSA_STRING OriginName,
            LogonType LogonType,
            UInt32 AuthenticationPackage,
            IntPtr AuthenticationInformation,
            UInt32 AuthenticationInformationLength,
            IntPtr LocalGroups,
            AccessToken.NativeHelpers.TOKEN_SOURCE SourceContext,
            out SafeLsaMemoryBuffer ProfileBuffer,
            out UInt32 ProfileBufferLength,
            out Luid LogonId,
            out SafeNativeHandle Token,
            out IntPtr Quotas,
            out UInt32 SubStatus);

        [DllImport("Secur32.dll")]
        public static extern UInt32 LsaLookupAuthenticationPackage(
            SafeLsaLogon LsaHandle,
            NativeHelpers.LSA_STRING PackageName,
            out UInt32 AuthenticationPackage);

        [DllImport("Advapi32.dll")]
        public static extern UInt32 LsaNtStatusToWinError(
            UInt32 Status);

        [DllImport("Secur32.dll")]
        public static extern UInt32 LsaRegisterLogonProcess(
            NativeHelpers.LSA_STRING LogonProcessName,
            out SafeLsaLogon LsaHandle,
            out IntPtr SecurityMode);
    }

    internal class SafeLsaMemoryBuffer : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeLsaMemoryBuffer() : base(true) { }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            UInt32 res = NativeMethods.LsaFreeReturnBuffer(handle);
            return res == 0;
        }
    }

    public class SafeLsaLogon : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeLsaLogon() : base(true) { }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            UInt32 res = NativeMethods.LsaDeregisterLogonProcess(handle);
            return res == 0;
        }
    }

    public class LsaException : Ansible.AccessToken.Win32Exception
    {
        public UInt32 LsaErrorCode;

        public LsaException(UInt32 errorCode, string message)
            : base((int)NativeMethods.LsaNtStatusToWinError(errorCode), message)
        {
            LsaErrorCode = errorCode;
        }
    }

    public class LsaLogonException : LsaException
    {
        public UInt32 SubStatus;

        public LsaLogonException(UInt32 errorCode, UInt32 subStatus, string message)
            : base(errorCode, message)
        {
            SubStatus = subStatus;
        }
    }

    public class LogonSessionData
    {
        public UInt32 Size;
        public Luid LogonId;
        public string UserName;
        public string LogonDomain;
        public string AuthenticationPackage;
        public LogonType LogonType;
        public UInt32 Session;
        public SecurityIdentifier Sid;
        public DateTime? LogonTime;
        public string LogonServer;
        public string DnsDomainName;
        public string Upn;
        public UInt32 UserFlags;
        public DateTime? LastSuccessfulLogon;
        public DateTime? LastFailedLogon;
        public UInt32 FailedAttemptCountSinceLastSuccessfulLogon;
        public string LogonScript;
        public string ProfilePath;
        public string HomeDirectory;
        public string HomeDirectoryDrive;
        public DateTime? LogoffTime;
        public DateTime? KickOffTime;
        public DateTime? PasswordLastSet;
        public DateTime? PasswordCanChange;
        public DateTime? PasswordMustChange;
    }

    public class LsaUtil
    {
        private static string ORIGIN_NAME = "ansible";
        private static string PACKAGE_NAME = "Negotiate";  // NEGOSSP_NAME

        public static SafeLsaLogon ConnectUntrusted()
        {
            SafeLsaLogon lsaHandle;
            UInt32 res = NativeMethods.LsaConnectUntrusted(out lsaHandle);
            if (res != 0)
                throw new LsaException(res, "LsaConnectUntrusted() failed");

            return lsaHandle;
        }

        public static UInt32 LookupAuthenticationPackage(SafeLsaLogon lsahandle, string name)
        {
            UInt32 packageId;
            UInt32 res = NativeMethods.LsaLookupAuthenticationPackage(lsahandle, name, out packageId);
            if (res != 0)
                throw new LsaException(res, String.Format("LsaLookupAuthenticationPackage({0}) failed", name));

            return packageId;
        }

        public static SafeLsaLogon RegisterLogonProcess(string processName)
        {
            NativeHelpers.LSA_STRING logonProcessName = processName;
            SafeLsaLogon lsaHandle;
            IntPtr securityMode;

            UInt32 res = NativeMethods.LsaRegisterLogonProcess(logonProcessName, out lsaHandle, out securityMode);
            if (res != 0)
                throw new LsaException(res, String.Format("LsaRegisterLogonProcess({0}) failed", processName));

            return lsaHandle;
        }

        public static SafeNativeHandle LogonUserInteractive(string username, string domain, string password,
            LogonType logonType, List<GroupInfo> localGroups)
        {
            int domainLength = Encoding.Unicode.GetByteCount(domain);
            int usernameLength = Encoding.Unicode.GetByteCount(username);
            int passwordLength = Encoding.Unicode.GetByteCount(password);
            int authInfoLength = Marshal.SizeOf(typeof(NativeHelpers.KERB_INTERACTIVE_LOGON)) + domainLength +
                usernameLength + passwordLength;

            SafeLsaLogon lsaLogon;
            if (localGroups != null && localGroups.Count > 0)
                lsaLogon = RegisterLogonProcess(ORIGIN_NAME);  // Requires SeTcbPrivilege, only use this if necessary.
            else
                lsaLogon = ConnectUntrusted();

            using (lsaLogon)
            using (SafeMemoryBuffer authBuffer = new SafeMemoryBuffer(authInfoLength))
            {
                IntPtr authBufferPtr = authBuffer.DangerousGetHandle();
                IntPtr domainPtr = IntPtr.Add(authBufferPtr, Marshal.SizeOf(
                    typeof(NativeHelpers.KERB_INTERACTIVE_LOGON)));
                IntPtr usernamePtr = IntPtr.Add(domainPtr, domainLength);
                IntPtr passwordPtr = IntPtr.Add(usernamePtr, usernameLength);

                // KERB_INTERACTIVE_LOGON has the same structure as MSV1_0_INTERACTIVE_LOGON (local accounts)
                NativeHelpers.KERB_INTERACTIVE_LOGON interativeLogon = new NativeHelpers.KERB_INTERACTIVE_LOGON()
                {
                    MessageType = 2,  // KerbInteractiveLogon/MsV1_0InteractiveLogon
                    LogonDomainName = NativeHelpers.LSA_UNICODE_STRING.FromString(domain, domainPtr),
                    UserName = NativeHelpers.LSA_UNICODE_STRING.FromString(username, usernamePtr),
                    Password = NativeHelpers.LSA_UNICODE_STRING.FromString(password, passwordPtr),
                };
                Marshal.StructureToPtr(interativeLogon, authBufferPtr, false);

                return InternalLogonUser(lsaLogon, logonType, authBufferPtr, authInfoLength, localGroups);
            }
        }

        public static SafeNativeHandle LogonUserS4U(string username, string domain, LogonType logonType,
            List<GroupInfo> localGroups)
        {
            int domainLength = Encoding.Unicode.GetByteCount(domain);
            int usernameLength = Encoding.Unicode.GetByteCount(username);
            int authInfoLength = Marshal.SizeOf(typeof(NativeHelpers.KERB_S4U_LOGON)) + domainLength + usernameLength;

            using (SafeLsaLogon lsaLogon = RegisterLogonProcess("ansible"))
            using (SafeMemoryBuffer authBuffer = new SafeMemoryBuffer(authInfoLength))
            {
                IntPtr authBufferPtr = authBuffer.DangerousGetHandle();
                IntPtr usernamePtr = IntPtr.Add(authBufferPtr, Marshal.SizeOf(typeof(NativeHelpers.KERB_S4U_LOGON)));
                IntPtr domainPtr = IntPtr.Add(usernamePtr, usernameLength);

                // KERB_S4U_LOGON has the same structure as MSV1_0_S4U_LOGON (local accounts)
                NativeHelpers.KERB_S4U_LOGON s4uLogon = new NativeHelpers.KERB_S4U_LOGON()
                {
                    MessageType = 12,  // KerbS4ULogon/MsV1_0S4ULogon
                    Flags = 0,
                    ClientUpn = NativeHelpers.LSA_UNICODE_STRING.FromString(username, usernamePtr),
                    ClientRealm = NativeHelpers.LSA_UNICODE_STRING.FromString(domain, domainPtr),
                };
                Marshal.StructureToPtr(s4uLogon, authBufferPtr, false);

                return InternalLogonUser(lsaLogon, logonType, authBufferPtr, authInfoLength, localGroups);
            }
        }

        public static LogonSessionData GetLogonSessionData(Luid authenticationId)
        {
            SafeLsaMemoryBuffer sessionDataPtr;
            UInt32 res = NativeMethods.LsaGetLogonSessionData(ref authenticationId, out sessionDataPtr);
            if (res != 0)
                throw new LsaException(res, "LsaGetLogonSessionData()");

            using (sessionDataPtr)
            {
                NativeHelpers.SECURITY_LOGON_SESSION_DATA sessionData = (NativeHelpers.SECURITY_LOGON_SESSION_DATA)
                    Marshal.PtrToStructure( sessionDataPtr.DangerousGetHandle(),
                    typeof(NativeHelpers.SECURITY_LOGON_SESSION_DATA));

                return new LogonSessionData()
                {
                    Size = sessionData.Size,
                    UserName = sessionData.UserName.ToString(),
                    LogonDomain = sessionData.LogonDomain.ToString(),
                    AuthenticationPackage = sessionData.AuthenticationPackage.ToString(),
                    LogonType = sessionData.LogonType,
                    Session = sessionData.Session,
                    Sid = new SecurityIdentifier(sessionData.Sid),
                    LogonTime = ConvertUnsafeFileTimeToDateTime(sessionData.LogonTime),
                    LogonServer = sessionData.LogonServer.ToString(),
                    DnsDomainName = sessionData.DnsDomainName.ToString(),
                    Upn = sessionData.Upn.ToString(),
                    UserFlags = sessionData.UserFlags,
                    LastSuccessfulLogon =
                        ConvertUnsafeFileTimeToDateTime(sessionData.LastLogonInfo.LastSuccessfulLogon),
                    LastFailedLogon = ConvertUnsafeFileTimeToDateTime(sessionData.LastLogonInfo.LastFailedLogon),
                    FailedAttemptCountSinceLastSuccessfulLogon =
                        sessionData.LastLogonInfo.FailedAttemptCountSinceLastSuccessfulLogon,
                    LogonScript = sessionData.LogonScript.ToString(),
                    ProfilePath = sessionData.ProfilePath.ToString(),
                    HomeDirectory = sessionData.HomeDirectory.ToString(),
                    HomeDirectoryDrive = sessionData.HomeDirectoryDrive.ToString(),
                    LogoffTime = ConvertUnsafeFileTimeToDateTime(sessionData.LogoffTime),
                    KickOffTime = ConvertUnsafeFileTimeToDateTime(sessionData.KickOffTime),
                    PasswordLastSet = ConvertUnsafeFileTimeToDateTime(sessionData.PasswordLastSet),
                    PasswordCanChange = ConvertUnsafeFileTimeToDateTime(sessionData.PasswordCanChange),
                    PasswordMustChange = ConvertUnsafeFileTimeToDateTime(sessionData.PasswordMustChange),
                };
            }
        }

        private static DateTime? ConvertUnsafeFileTimeToDateTime(Int64 value)
        {
            if (value == Int64.MaxValue || value == 0)
                return null;
            return DateTime.FromFileTime(value);
        }

        private static SafeNativeHandle InternalLogonUser(SafeLsaLogon lsaHandle, LogonType logonType,
            IntPtr authInfo, int authInfoLength, List<GroupInfo> localGroups)
        {
            TokenSource source = new TokenSource()
            {
                Name = ORIGIN_NAME,
            };
            if (!NativeMethods.AllocateLocallyUniqueId(out source.Id))
                throw new AccessToken.Win32Exception("AllocateLocallyUniqueID() failed");

            return LogonUser(lsaHandle, ORIGIN_NAME, logonType, PACKAGE_NAME, authInfo, (UInt32)authInfoLength,
                localGroups, source);
        }

        private static SafeNativeHandle LogonUser(SafeLsaLogon lsaHandle, string originName, LogonType logonType,
            string authPackage, IntPtr authInfo, UInt32 authInfoLength, List<GroupInfo> localGroups,
            TokenSource source)
        {
            NativeHelpers.LSA_STRING origin = originName;
            UInt32 authPackageId = LookupAuthenticationPackage(lsaHandle, authPackage);

            AccessToken.NativeHelpers.TOKEN_SOURCE sourceContext = new AccessToken.NativeHelpers.TOKEN_SOURCE()
            {
                SourceName = source.Name.ToCharArray(),
                SourceIdentifier = source.Id,
            };

            int tokenGroupSize = 0;
            int sidOffset = 0;
            SafeMemoryBuffer tokenGroups;
            if (localGroups != null && localGroups.Count > 0)
            {
                tokenGroupSize += Marshal.SizeOf(typeof(AccessToken.NativeHelpers.TOKEN_GROUPS));
                tokenGroupSize += Marshal.SizeOf(typeof(AccessToken.NativeHelpers.SID_AND_ATTRIBUTES)) *
                    (localGroups.Count - 1);
                sidOffset = tokenGroupSize;  // Record where we need to start placing the SID structures.

                foreach (GroupInfo group in localGroups)
                    tokenGroupSize += group.Sid.BinaryLength;

                tokenGroups = new SafeMemoryBuffer(tokenGroupSize);
            }
            else
                tokenGroups = new SafeMemoryBuffer(IntPtr.Zero);

            using (tokenGroups)
            {
                if (localGroups != null && localGroups.Count > 0)
                {
                    AccessToken.NativeHelpers.TOKEN_GROUPS groups = new AccessToken.NativeHelpers.TOKEN_GROUPS()
                    {
                        GroupCount = (UInt32)localGroups.Count,
                        Groups = new AccessToken.NativeHelpers.SID_AND_ATTRIBUTES[1],
                    };
                    Marshal.StructureToPtr(groups, tokenGroups.DangerousGetHandle(), false);

                    // x86 == 4, x64 == 8, this is variable due to the packing logic of the TOKEN_GROUPS structure.
                    int offset = IntPtr.Size;
                    foreach (GroupInfo group in localGroups)
                    {
                        byte[] sidBytes = new byte[group.Sid.BinaryLength];
                        group.Sid.GetBinaryForm(sidBytes, 0);

                        IntPtr sidPointer = IntPtr.Add(tokenGroups.DangerousGetHandle(), sidOffset);
                        sidOffset += sidBytes.Length;
                        Marshal.Copy(sidBytes, 0, sidPointer, sidBytes.Length);

                        AccessToken.NativeHelpers.SID_AND_ATTRIBUTES sidAttrs =
                            new AccessToken.NativeHelpers.SID_AND_ATTRIBUTES()
                            {
                                Attributes = (UInt32)group.Attributes,
                                Sid = sidPointer,
                            };
                        Marshal.StructureToPtr(sidAttrs, IntPtr.Add(tokenGroups.DangerousGetHandle(), offset), false);
                        offset += Marshal.SizeOf(sidAttrs);
                    }
                }

                SafeLsaMemoryBuffer profileBuffer;
                UInt32 profileBufferLength;
                Luid logonId;
                SafeNativeHandle token;
                IntPtr quotaLimits;
                UInt32 subStatus;

                UInt32 res = NativeMethods.LsaLogonUser(lsaHandle, origin, logonType, authPackageId, authInfo,
                    authInfoLength, tokenGroups.DangerousGetHandle(), sourceContext, out profileBuffer,
                    out profileBufferLength, out logonId, out token, out quotaLimits, out subStatus);

                if (res != 0)
                    throw new LsaLogonException(res, subStatus, "LsaLogonUser() failed");

                profileBuffer.Dispose();
                return token;
            }
        }
    }
}
