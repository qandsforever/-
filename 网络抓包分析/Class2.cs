using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Linq;

namespace 网络抓包分析
{

    /// <summary>
    /// 通过API获取进程图标
    /// </summary>
    public class ProcessAPI
    {
        [DllImport("Shell32.dll")]
        private static extern int SHGetFileInfo
        (
        string pszPath,
        uint dwFileAttributes,
        out SHFILEINFO psfi,
        uint cbfileInfo,
        SHGFI uFlags
        );

        [StructLayout(LayoutKind.Sequential)]
        private struct SHFILEINFO
        {
            public SHFILEINFO(bool b)
            {
                hIcon = IntPtr.Zero; iIcon = 0; dwAttributes = 0; szDisplayName = ""; szTypeName = "";
            }
            public IntPtr hIcon;
            public int iIcon;
            public uint dwAttributes;
            [MarshalAs(UnmanagedType.LPStr, SizeConst = 260)]
            public string szDisplayName;
            [MarshalAs(UnmanagedType.LPStr, SizeConst = 80)]
            public string szTypeName;
        };

        private enum SHGFI
        {
            SmallIcon = 0x00000001,
            LargeIcon = 0x00000000,
            Icon = 0x00000100,
            DisplayName = 0x00000200,
            Typename = 0x00000400,
            SysIconIndex = 0x00004000,
            UseFileAttributes = 0x00000010
        }
        //获取进程图标
        public static Icon GetIcon(string strPath, bool bSmall)
        {
            SHFILEINFO info = new SHFILEINFO(true);
            int cbFileInfo = Marshal.SizeOf(info);
            SHGFI flags;
            if (bSmall)
                flags = SHGFI.Icon | SHGFI.SmallIcon | SHGFI.UseFileAttributes;
            else
                flags = SHGFI.Icon | SHGFI.LargeIcon | SHGFI.UseFileAttributes;

            SHGetFileInfo(strPath, 256, out info, (uint)cbFileInfo, flags);
            return Icon.FromHandle(info.hIcon);
        }


        public static netProcessInfo GetProcessInfo(int pid)
        {
            netProcessInfo npi = new netProcessInfo();

            var mgrSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_Process Where processid=" + pid).Get().Cast<ManagementBaseObject>();
            if (mgrSearcher.Count() > 0)
            {
                var name = mgrSearcher.First().Properties.Cast<PropertyData>().Where(x => x.Name == "Name").First();
                var path = mgrSearcher.First().Properties.Cast<PropertyData>().Where(x => x.Name == "ExecutablePath").First();

                if (name != null && name.Value != null)
                {
                    npi.name = name.Value.ToString().Split('.')[0];
                }
                else
                {
                    npi.name = "未知";
                }
                if (path != null && path.Value != null)
                {
                    npi.path = path.Value.ToString();
                    npi.icon = GetIcon(path.Value.ToString(), true);
                }
                else
                {
                    npi.path = npi.name;
                    npi.icon = Properties.Resources.ConfigureWERTask;
                }

                if (npi.icon == null)
                {
                    npi.icon = Properties.Resources.ConfigureWERTask;
                }
            }
            else
            {
               
                npi.name = "未知";
                npi.path = "";
                npi.icon = Properties.Resources.ConfigureWERTask;
            }
            return npi;
        }

        //获取进程图标
        public static Icon GetIcon(int pid, bool bSmall)
        {

            try
            {

                var p = System.Diagnostics.Process.GetProcessById(pid);
                return GetIcon(p.MainModule.FileName, bSmall);
            }
            catch 
            {
                return null;
            }
        }

        //获取进程名称
        public static string GetProcessNameByPID(int processID)
        {
            //could be an error here if the process die before we can get his name
            try
            {
                Process p = Process.GetProcessById((int)processID);
                return p.ProcessName;
            }
            catch
            {
                return "Unknown";
            }
        }
    }
}