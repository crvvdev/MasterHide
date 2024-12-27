using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using FileAttributes = System.IO.FileAttributes;

namespace MasterHideGUI
{
    public static class WinAPI
    {
        [Flags]
        public enum FileAccess : uint
        {
            GenericRead = 0x80000000,
            GenericWrite = 0x40000000,
            GenericExecute = 0x20000000,
            GenericAll = 0x10000000
        }

        [Flags]
        public enum FileShare : uint
        {
            Zero = 0x00000000,
            FileShareDelete = 0x00000004,
            FileShareRead = 0x00000001,
            FileShareWrite = 0x00000002
        }

        public enum FileMode : uint
        {
            CreateNew = 1,
            CreateAlways = 2,
            OpenExisting = 3,
            OpenAlways = 4,
            TruncateExisting = 5
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern SafeFileHandle CreateFile(
          string lpFileName,
          [MarshalAs(UnmanagedType.U4)] FileAccess dwDesiredAccess,
          [MarshalAs(UnmanagedType.U4)] FileShare dwShareMode,
          IntPtr lpSecurityAttributes,
          [MarshalAs(UnmanagedType.U4)] FileMode dwCreationDisposition,
          [MarshalAs(UnmanagedType.U4)] FileAttributes dwFlagsAndAttributes,
          IntPtr hTemplateFile);

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern int RtlDosPathNameToNtPathName_U_WithStatus(
            string DosFileName,
            out UNICODE_STRING NtFileName,
            IntPtr FilePart,
            IntPtr Reserved);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint IoControlCode,
            [MarshalAs(UnmanagedType.AsAny)]
            [In] object InBuffer,
            uint nInBufferSize,
            [MarshalAs(UnmanagedType.AsAny)]
            [Out] object OutBuffer,
            uint nOutBufferSize,
            ref uint pBytesReturned,
            [In] IntPtr Overlapped
            );

        public const int ERROR_SERVICE_DOES_NOT_EXIST = 1060;

        [Flags]
        public enum SCM_ACCESS : uint
        {
            SC_MANAGER_CONNECT = 0x0001,
            SC_MANAGER_CREATE_SERVICE = 0x0002,
            SC_MANAGER_ENUMERATE_SERVICE = 0x0004,
            SC_MANAGER_LOCK = 0x0008,
            SC_MANAGER_QUERY_LOCK_STATUS = 0x0010,
            SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020,
            SC_MANAGER_ALL_ACCESS = 0xF003F,
        }

        [Flags]
        public enum SERVICE_ACCESS : uint
        {
            SERVICE_QUERY_CONFIG = 0x0001,
            SERVICE_CHANGE_CONFIG = 0x0002,
            SERVICE_QUERY_STATUS = 0x0004,
            SERVICE_ENUMERATE_DEPENDENTS = 0x0008,
            SERVICE_START = 0x0010,
            SERVICE_STOP = 0x0020,
            SERVICE_PAUSE_CONTINUE = 0x0040,
            SERVICE_INTERROGATE = 0x0080,
            SERVICE_USER_DEFINED_CONTROL = 0x0100,
            SERVICE_ALL_ACCESS = 0xF01FF
        }

        public enum SERVICE_TYPE : uint
        {
            SERVICE_KERNEL_DRIVER = 0x00000001,
            SERVICE_FILE_SYSTEM_DRIVER = 0x00000002
        }

        public enum SERVICE_START : uint
        {
            SERVICE_BOOT_START = 0x00000000,
            SERVICE_SYSTEM_START = 0x00000001,
            SERVICE_AUTO_START = 0x00000002,
            SERVICE_DEMAND_START = 0x00000003,
            SERVICE_DISABLED = 0x00000004
        }

        public enum SERVICE_ERROR : uint
        {
            SERVICE_ERROR_IGNORE = 0x00000000,
            SERVICE_ERROR_NORMAL = 0x00000001,
            SERVICE_ERROR_SEVERE = 0x00000002,
            SERVICE_ERROR_CRITICAL = 0x00000003
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, SCM_ACCESS dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr CreateService(
            IntPtr hSCManager,
            string lpServiceName,
            string lpDisplayName,
            SERVICE_ACCESS dwDesiredAccess,
            SERVICE_TYPE dwServiceType,
            SERVICE_START dwStartType,
            SERVICE_ERROR dwErrorControl,
            string lpBinaryPathName,
            string lpLoadOrderGroup,
            IntPtr lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DeleteService(IntPtr hService);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, SERVICE_ACCESS dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);
    }

    class DriverManager
    {
        private SafeFileHandle _deviceHandle { get; set; }
        private const string _serviceName = "MasterHide";
        private const string _driverFileName = _serviceName + ".sys";
        private const string _deviceName = "{EDC00A52-CBB9-490E-89A3-69E3FFF137BA}";

        public DriverManager()
        {
            try
            {
                GetDeviceHandle();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open handle to driver, MasterHide service is probably not running! {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Check if device handle is valid
        /// </summary>
        /// <returns>true on success, otherwise false</returns>
        private bool IsDeviceHandleValid()
        {
            return (_deviceHandle != null && !_deviceHandle.IsInvalid && !_deviceHandle.IsClosed);
        }

        /// <summary>
        /// Get or update the device handle, if device is already valid it does nothing.
        /// </summary>
        public void GetDeviceHandle()
        {
            if (IsDeviceHandleValid())
            {
                return;
            }

            _deviceHandle = WinAPI.CreateFile($@"\\.\{_deviceName}",
                WinAPI.FileAccess.GenericRead | WinAPI.FileAccess.GenericWrite,
                WinAPI.FileShare.Zero,
                IntPtr.Zero,
                WinAPI.FileMode.OpenExisting,
                FileAttributes.Normal,
                IntPtr.Zero);

            if (_deviceHandle.IsInvalid)
            {
                throw new Win32Exception($"CreateFile failed with error {Marshal.GetLastWin32Error()}");
            }
        }

        /// <summary>
        /// Get ServiceController for MasterHide service
        /// </summary>
        /// <returns>ServiceController on success, otherwise null</returns>
        public ServiceController GetServiceController()
        {
            return ServiceController.GetDevices().FirstOrDefault(s => s.ServiceName == _serviceName);
        }

        /// <summary>
        /// Updates MasterHide driver service parameters
        /// </summary>
        /// <param name="hookType">Desired hook type</param>
        public void UpdateServiceParameters(HookType hookType)
        {
            string keyPath = $@"SYSTEM\CurrentControlSet\Services\{_serviceName}\Parameters";

            using (RegistryKey serviceKey = Registry.LocalMachine.OpenSubKey(keyPath, true) ??
                                            Registry.LocalMachine.CreateSubKey(keyPath))
            {
                if (serviceKey == null)
                {
                    throw new Exception("Failed to open or create registry key.");
                }

                serviceKey.SetValue("HookType", (int)hookType, RegistryValueKind.DWord);
            }
        }

        /// <summary>
        /// Try start MasterHide service using ServiceController
        /// </summary>
        public void StartService()
        {
            try
            {
                ServiceController sc = GetServiceController();
                if (sc == null)
                {
                    throw new Exception("MasterHide service not found!");
                }

                if (sc.Status != ServiceControllerStatus.Running)
                {
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                }

                // Need to update device handle
                //
                GetDeviceHandle();
            }
            catch (InvalidOperationException ex)
            {
                throw new Exception($"Win32 error code: {Marshal.GetLastWin32Error()}", ex);
            }
            catch (Win32Exception ex)
            {
                throw new Exception($"Win32 error code: {ex.NativeErrorCode}, Message: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Try stop MasterHide service using ServiceController
        /// </summary>
        public void StopService()
        {
            try
            {
                ServiceController sc = GetServiceController();
                if (sc == null)
                {
                    throw new Exception("MasterHide service not found!");
                }

                if (IsDeviceHandleValid())
                {
                    _deviceHandle.Close();
                    _deviceHandle = null;
                }

                if (sc.Status == ServiceControllerStatus.Running)
                {
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                }
            }
            catch (InvalidOperationException ex)
            {
                throw new Exception($"Invalid operation error: {ex.Message}", ex);
            }
            catch (Win32Exception ex)
            {
                throw new Exception($"Windows error code: {ex.NativeErrorCode}, Message: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Try install MasterHide service
        /// </summary>
        /// <param name="hookType"></param>
        public void InstallService(string driverPath, HookType hookType)
        {
            if (GetServiceController() != null)
            {
                throw new Exception("MasterHide service is already installed!");
            }

            string finalDriverPath;

            if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess)
            {
                finalDriverPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Sysnative", _driverFileName);
            }
            else
            {
                finalDriverPath = Path.Combine(Environment.SystemDirectory, _driverFileName);
            }

            // Copy file to system directory
            //
            File.Copy(driverPath, finalDriverPath, true);

            IntPtr scmHandle = WinAPI.OpenSCManager(null, null, WinAPI.SCM_ACCESS.SC_MANAGER_ALL_ACCESS);
            if (scmHandle == IntPtr.Zero)
            {
                throw new Win32Exception($"OpenSCManager failed with error {Marshal.GetLastWin32Error()}");
            }

            IntPtr serviceHandle = WinAPI.CreateService(
                scmHandle,
                _serviceName,
                _serviceName,
                WinAPI.SERVICE_ACCESS.SERVICE_ALL_ACCESS,
                WinAPI.SERVICE_TYPE.SERVICE_KERNEL_DRIVER,
                WinAPI.SERVICE_START.SERVICE_DEMAND_START,
                WinAPI.SERVICE_ERROR.SERVICE_ERROR_NORMAL,
                finalDriverPath,
                null,
                IntPtr.Zero,
                null,
                null,
                null);

            if (serviceHandle == IntPtr.Zero)
            {
                throw new Win32Exception($"CreateService failed with error {Marshal.GetLastWin32Error()}");
            }

            UpdateServiceParameters(hookType);

            WinAPI.CloseServiceHandle(serviceHandle);
            WinAPI.CloseServiceHandle(scmHandle);
        }

        /// <summary>
        /// Try uninstall MasterHide service
        /// </summary>
        public void UninstallService()
        {
            StopService();

            IntPtr scmHandle = WinAPI.OpenSCManager(null, null, WinAPI.SCM_ACCESS.SC_MANAGER_ALL_ACCESS);
            if (scmHandle == IntPtr.Zero)
            {
                throw new Win32Exception($"OpenSCManager failed with error {Marshal.GetLastWin32Error()}");
            }

            IntPtr serviceHandle = WinAPI.OpenService(scmHandle, _serviceName, WinAPI.SERVICE_ACCESS.SERVICE_ALL_ACCESS);
            if (serviceHandle == IntPtr.Zero)
            {
                throw new Win32Exception($"OpenService failed with error {Marshal.GetLastWin32Error()}");
            }

            if (!WinAPI.DeleteService(serviceHandle))
            {
                throw new Win32Exception($"DeleteService failed with error {Marshal.GetLastWin32Error()}");
            }

            WinAPI.CloseServiceHandle(serviceHandle);
            WinAPI.CloseServiceHandle(scmHandle);
        }

        /// <summary>
        /// Try reinstall MasterHide service
        /// </summary>
        /// <param name="hookType">Desired hook type</param>
        public void ReinstallService(string driverPath, HookType hookType)
        {
            UninstallService();
            InstallService(driverPath, hookType);
        }

        /// <summary>
        /// Send IOCTL to MasterHide driver
        /// </summary>
        /// <typeparam name="T">Input type</typeparam>
        /// <param name="ioctl">IOCTL code</param>
        /// <param name="input">Input param</param>
        /// <returns>true on success, otherwise false</returns>
        private bool SendIoControl<T>(uint ioctl, T input)
        {
            uint returnedBytes = 0;
            var inputSize = (uint)Marshal.SizeOf(typeof(T));
            return WinAPI.DeviceIoControl(_deviceHandle, ioctl, input, inputSize, null, 0, ref returnedBytes, IntPtr.Zero);
        }

        /// <summary>
        /// Send process rule for MasterHide driver
        /// </summary>
        /// <param name="imageFileName">Image file name</param>
        /// <param name="policyFlags">Policy flags</param>
        public void SendProcessRule(string imageFileName, long policyFlags)
        {
            int status = WinAPI.RtlDosPathNameToNtPathName_U_WithStatus(imageFileName, out var ntFileName, IntPtr.Zero, IntPtr.Zero);
            if (status != 0)
            {
                throw new Win32Exception($"RtlDosPathNameToNtPathName_U_WithStatus failed with status {status}");
            }

            if (!SendIoControl<PROCESS_RULE>(IoctlCodes.IOCTL_MASTERHIDE_ADD_RULE, new PROCESS_RULE { ImageFileName = ntFileName, PolicyFlags = policyFlags, ProcessId = 0, UseProcessId = false }))
            {
                if (!SendIoControl<PROCESS_RULE>(IoctlCodes.IOCTL_MASTERHIDE_UPDATE_RULE, new PROCESS_RULE { ImageFileName = ntFileName, PolicyFlags = policyFlags, ProcessId = 0, UseProcessId = false }))
                {
                    throw new Win32Exception($"DeviceIoControl failed with error {Marshal.GetLastWin32Error()}");
                }
            }
        }

        public void RemoveProcessRule(string imageFileName)
        {
            int status = WinAPI.RtlDosPathNameToNtPathName_U_WithStatus(imageFileName, out var ntFileName, IntPtr.Zero, IntPtr.Zero);
            if (status != 0)
            {
                throw new Win32Exception($"RtlDosPathNameToNtPathName_U_WithStatus failed with status {status}");
            }

            if (!SendIoControl<PROCESS_RULE>(IoctlCodes.IOCTL_MASTERHIDE_REMOVE_RULE, new PROCESS_RULE { ImageFileName = ntFileName, PolicyFlags = 0, ProcessId = 0, UseProcessId = false }))
            {
                throw new Win32Exception($"DeviceIoControl failed with error {Marshal.GetLastWin32Error()}");
            }
        }
    }
}
